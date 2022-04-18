/*
 * Copyright (C) 2004-2020 ZNC, see the NOTICE file for details.
 * Copyright (C) 2008 Heiko Hund <heiko@ist.eigentlich.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @class CSASLAuthMod
 * @author Heiko Hund <heiko@ist.eigentlich.net>
 * @brief SASL authentication module for znc.
 */

#include <znc/znc.h>
#include <znc/IRCNetwork.h>
#include <znc/User.h>
#include <znc/MD5.h>

#include <sasl/sasl.h>
#include <sstream>

class CSASLAuthMod : public CModule {
  public:
    MODCONSTRUCTOR(CSASLAuthMod) {
        m_Cache.SetTTL(60000 /*ms*/);
        m_bWebIrcEnabled = false;
        m_cbs[0].id = SASL_CB_GETOPT;
        m_cbs[0].proc = reinterpret_cast<int (*)()>(CSASLAuthMod::getopt);
        m_cbs[0].context = this;
        m_cbs[1].id = SASL_CB_LIST_END;
        m_cbs[1].proc = nullptr;
        m_cbs[1].context = nullptr;

        AddHelpCommand();
        AddCommand("Show", "", t_d("Shows current settings"),
                   [=](const CString& sLine) { ShowCommand(sLine); });
        AddCommand("CreateUsers", t_d("yes|clone <username>|no"),
                   t_d("Create ZNC users upon first successful login, "
                       "optionally from a template"),
                   [=](const CString& sLine) { CreateUsersCommand(sLine); });
        AddCommand("SetImpersonateAccount", t_d("username password"),
                   t_d("Set the username and password for the SASL "
                       "Impersonaton Account"),
                   [=](const CString& sLine) { SetImpersonateAccount(sLine);});
        AddCommand("SetWebIrc", t_d("username password"),
                   t_d("Set the username and password for WebIRC"),
                   [=](const CString& sLine) { SetWebIrc(sLine);});
        AddCommand("SetWebIrcHost", t_d("hostname"),
                   t_d("Set the hostname used for WebIRC"),
                   [=](const CString& sLine) { SetWebIrcHost(sLine);});
        AddCommand("SetUserSalt", t_d("salt"),
                   t_d("Set the salt used when hashing usernames"),
                   [=](const CString& sLine) { SetUserSalt(sLine);});
        AddCommand("SetNetworkName", t_d("network"),
                   t_d("Set the network name used for newly created "
                       "accounts"),
                   [=](const CString& sLine) { SetNetworkName(sLine);});
        AddCommand("SetServer", t_d("server port ssl"),
                   t_d("Set the server and port used for newly created "
                       "accounts"),
                   [=](const CString& sLine) { SetServer(sLine);});
    }

    ~CSASLAuthMod() override { sasl_done(); }

    void OnModCommand(const CString& sCommand) override {
        if (GetUser()->IsAdmin()) {
            HandleCommand(sCommand);
        } else {
            PutModule(t_s("Access denied"));
        }
    }

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        VCString vsArgs;
        VCString::const_iterator it;
        sArgs.Split(" ", vsArgs, false);

        for (it = vsArgs.begin(); it != vsArgs.end(); ++it) {
            if (it->Equals("saslauthd") || it->Equals("auxprop")) {
                m_sMethod += *it + " ";
            } else {
                if (it->Equals("webirc")) {
                    m_bWebIrcEnabled = true;
                } else if (it->Equals("impersonation")) {
                    m_bSaslImpersonateEnabled = true;
                } else {
                    CUtils::PrintError(
                        t_f("Ignoring invalid SASL pwcheck method: {1}")(*it));
                    sMessage = t_s("Ignored invalid SASL pwcheck method");
                }
            }
        }

        m_sMethod.TrimRight();

        if (m_sMethod.empty()) {
            sMessage =
                t_s("Need a pwcheck method as argument (saslauthd, auxprop)");
            return false;
        }

        if (sasl_server_init(nullptr, nullptr) != SASL_OK) {
            sMessage = t_s("SASL Could Not Be Initialized - Halting Startup");
            return false;
        }

        return true;
    }

    EModRet OnLoginAttempt(std::shared_ptr<CAuthBase> Auth) override {
        const CString& sUsername = Auth->GetUsername();
        const CString& sPassword = Auth->GetPassword();
        CUser* pUser(CZNC::Get().FindUser(sUsername.AsLower()));
        sasl_conn_t* sasl_conn(nullptr);
        bool bSuccess = false;

        if (!pUser && !CreateUser()) {
            return CONTINUE;
        }

        const CString sCacheKey(CString(sUsername + ":" + sPassword).MD5());
        if (m_Cache.HasItem(sCacheKey)) {
            bSuccess = true;
            DEBUG("saslauth: Found [" + sUsername + "] in cache");
        } else if (sasl_server_new("znc", nullptr, nullptr, nullptr, nullptr,
                                   m_cbs, 0, &sasl_conn) == SASL_OK &&
                   sasl_checkpass(sasl_conn, sUsername.AsLower().c_str(),
                                  sUsername.AsLower().size(), sPassword.c_str(),
                                  sPassword.size()) == SASL_OK) {
            m_Cache.AddItem(sCacheKey);

            DEBUG("saslauth: Successful SASL authentication [" + sUsername +
                  "]");

            bSuccess = true;
        }

        sasl_dispose(&sasl_conn);

        if (bSuccess) {
            if (!pUser) {
                CString sErr;
                pUser = new CUser(sUsername.AsLower());

                if (ShouldCloneUser()) {
                    CUser* pBaseUser = CZNC::Get().FindUser(CloneUser());

                    if (!pBaseUser) {
                        DEBUG("saslauth: Clone User [" << CloneUser()
                                                       << "] User not found");
                        delete pUser;
                        pUser = nullptr;
                    }

                    if (pUser && !pUser->Clone(*pBaseUser, sErr)) {
                        DEBUG("saslauth: Clone User [" << CloneUser()
                                                       << "] failed: " << sErr);
                        delete pUser;
                        pUser = nullptr;
                    }
                }

                pUser->SetNick(sUsername);
                pUser->SetAltNick(sUsername + "_");
                pUser->SetIdent(sUsername);
                pUser->SetRealName(sUsername);
                CString sAddNetworkError;
                CIRCNetwork* pNetwork = pUser->AddNetwork(GetNV("networkname"), sAddNetworkError);
                if (pNetwork) {
                    pNetwork->AddServer(GetNV("server"), GetNV("port").ToUShort(), "", GetNV("ssl").ToBool());

                    if (pUser) {
                        // "::" is an invalid MD5 hash, so user won't be able to
                        // login by usual method
                        pUser->SetPass("::", CUser::HASH_MD5, "::");
                    }

                    if (pUser && !CZNC::Get().AddUser(pUser, sErr)) {
                        DEBUG("saslauth: Add user [" << sUsername
                                                 << "] failed: " << sErr);
                        delete pUser;
                        pUser = nullptr;
                    }
                    if (m_bSaslImpersonateEnabled) {
                        CString sModRet;
                        if (pNetwork->GetModules().LoadModule("sasl", "", CModInfo::NetworkModule, pUser, pNetwork, sModRet))
                        {
                            CModule* pModule = pNetwork->GetModules().FindModule("sasl");
                            if (pModule) {
                                pModule->SetNV("saslimpersonation", "yes");
                                pModule->SetNV("impersonationuser", sUsername);
                                pModule->SetNV("username", GetNV("impersonationusername"));
                                pModule->SetNV("password", GetNV("impersonationpassword"));
                                pModule->SetNV("require_auth", "yes");
                                pModule->SetNV("mechanisms", "PLAIN");
                            }
                        }
                        else DEBUG("saslauth: Failure loading sasl module for created user [" << sUsername << "] ");
                    }
                }
                else DEBUG("saslauth: Failure adding network for created user [" << sUsername << "]: " << sAddNetworkError);
            }

            if (pUser) {
                Auth->AcceptLogin(*pUser);
                return HALT;
            }
        }

        return CONTINUE;
    }

    virtual EModRet OnIRCRegistration(CString& sPass, CString& sNick,
            CString& sIdent, CString& sRealName)
    {
        if (m_bWebIrcEnabled) {
            CUser* pUser = CModule::GetUser();
            CIRCNetwork* pNetwork = CModule::GetNetwork();
            if (pUser != NULL && !(pNetwork->GetName().CaseCmp(GetNV("networkname")))) {
                std::ostringstream sWebIrcMsg;
                CString sUsername = pUser->GetUserName();
                CMD5 md5(sUsername + GetNV("usersalt"));
                uint8* hashBytes = downsample(md5.GetHash());
                unsigned int hashInts[3] = { hashBytes[0], hashBytes[1], hashBytes[2] };
                sWebIrcMsg << "WEBIRC " << GetNV("webircpassword") << " " << GetNV("webircusername") << " " << sUsername <<
                GetNV("webirchost") << " 255." << hashInts[0] << "." << hashInts[1] << "." << hashInts[2];
                CModule::PutIRC(sWebIrcMsg.str());
                delete[] hashBytes;
            }
        }

        return CONTINUE;
    }


    const CString& GetMethod() const { return m_sMethod; }

    void ShowCommand(const CString& sLine) {
        if (!CreateUser()) {
            PutModule(t_s("We will not create users on their first login"));
        } else if (ShouldCloneUser()) {
            PutModule(
                t_f("We will create users on their first login, using user "
                    "[{1}] as a template")(CloneUser()));
        } else {
            PutModule(t_s("We will create users on their first login"));
        }
    }

    void CreateUsersCommand(const CString& sLine) {
        CString sCreate = sLine.Token(1);
        if (sCreate == "no") {
            DelNV("CloneUser");
            SetNV("CreateUser", CString(false));
            PutModule(t_s("We will not create users on their first login"));
        } else if (sCreate == "yes") {
            DelNV("CloneUser");
            SetNV("CreateUser", CString(true));
            PutModule(t_s("We will create users on their first login"));
        } else if (sCreate == "clone" && !sLine.Token(2).empty()) {
            SetNV("CloneUser", sLine.Token(2));
            SetNV("CreateUser", CString(true));
            PutModule(
                t_f("We will create users on their first login, using user "
                    "[{1}] as a template")(sLine.Token(2)));
        } else {
            PutModule(
                t_s("Usage: CreateUsers yes, CreateUsers no, or CreateUsers "
                    "clone <username>"));
        }
    }

    void SetServer(const CString& sLine) {
        SetNV("server", sLine.Token(1));
        SetNV("port", sLine.Token(2));
        SetNV("ssl", sLine.Token(3));
        PutModule(t_f("Server and port used for newly created accounts has "
                  "been set to [{1}]")(GetNV("server") + ":" + 
                  (GetNV("ssl").ToBool() ? "+" + GetNV("port") :
                  GetNV("port"))));
    }

    void SetNetworkName(const CString& sLine) {
        SetNV("networkname", sLine.Token(1));
        PutModule(t_f("Network name used for newly created accounts has been"
                  " set to [{1}]")(GetNV("networkname")));
    }

    void SetImpersonateAccount(const CString& sLine) {
        SetNV("impersonationusername", sLine.Token(1));
        SetNV("impersonationpassword", sLine.Token(2));
        PutModule(t_f("SASL Impersonaton Account Username has been set "
                      "to [{1}]")(GetNV("impersonationusername")));
        PutModule(t_f("SASL Impersonaton Account Password has been set to [{1}]")(GetNV("impersonationpassword")));
    }

    void SetWebIrc(const CString& sLine) {
        SetNV("webircusername", sLine.Token(1));
        SetNV("webircpassword", sLine.Token(2));
        PutModule(t_f("WebIRC Username has been set to [{1}]")(GetNV("webircusername")));
        PutModule(t_f("WebIRC Password has been set to [{1}]")(GetNV("webircpassword")));
    }

    void SetWebIrcHost(const CString& sLine) {
        SetNV("webirchost", sLine);
        PutModule(t_f("WebIRC hostname has been set to [{1}]")(GetNV("webirchost")));
    }

    void SetUserSalt(const CString& sLine) {
        SetNV("usersalt", sLine.Token(1));
        PutModule(t_f("User salt has been set to [{1}]")(GetNV("usersalt")));
    }

    bool CreateUser() const { return GetNV("CreateUser").ToBool(); }

    CString CloneUser() const { return GetNV("CloneUser"); }

    bool ShouldCloneUser() { return !GetNV("CloneUser").empty(); }

  protected:
    TCacheMap<CString> m_Cache;

    sasl_callback_t m_cbs[2];
    CString m_sMethod;
    bool m_bWebIrcEnabled;
    bool m_bSaslImpersonateEnabled;

    static int getopt(void* context, const char* plugin_name,
                      const char* option, const char** result, unsigned* len) {
        if (CString(option).Equals("pwcheck_method")) {
            *result = ((CSASLAuthMod*)context)->GetMethod().c_str();
            return SASL_OK;
        }

        return SASL_CONTINUE;
    }

	/** Downsamples a 128bit result to 32bits (md5 -> unsigned int).
	 * @param[in] i 128bit result to downsample.
	 * @return downsampled result.

	 */
	static inline uint8* downsample(unsigned char *i)
	{
		uint8* r = new uint8[3];
		r[0] = i[0] ^ i[1] ^ i[2] ^ i[3] ^ i[4];
		r[1] = i[5] ^ i[6] ^ i[7] ^ i[8] ^ i[9];
		r[2] = i[10] ^ i[11] ^ i[12] ^ i[13] ^ i[14] ^ i[15];
		return r;
	}
};

template <>
void TModInfo<CSASLAuthMod>(CModInfo& Info) {
    Info.SetWikiPage("cyrusauth");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText(Info.t_s(
        "This global module takes up to two arguments - the methods of "
        "authentication - auxprop and saslauthd"));
}

GLOBALMODULEDEFS(
    CSASLAuthMod,
    t_s("Allow users to authenticate via SASL password verification method"))
