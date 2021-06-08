/*
 * Copyright (C) 2004-2021 ZNC, see the NOTICE file for details.
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

#include <sasl/sasl.h>
#include <znc/IRCNetwork.h>
#include <znc/MD5.h>
#include <znc/User.h>
#include <znc/znc.h>

#include <sstream>

class CSASLAuthMod : public CModule {
  public:
    MODCONSTRUCTOR(CSASLAuthMod) {
        m_Cache.SetTTL(60000 /*ms*/);

        m_cbs[0].id = SASL_CB_GETOPT;
        m_cbs[0].proc = reinterpret_cast<int (*)()>(CSASLAuthMod::getopt);
        m_cbs[0].context = this;
        m_cbs[1].id = SASL_CB_LIST_END;
        m_cbs[1].proc = nullptr;
        m_cbs[1].context = nullptr;

        m_bWEBIRC = false;
        m_bSaslImpersonation = false;

        AddHelpCommand();
        AddCommand("Show", "", t_d("Shows current settings"),
                   [=](const CString& sLine) { ShowCommand(sLine); });
        AddCommand("CreateUsers", t_d("yes|clone <username>|no"),
                   t_d("Create ZNC users upon first successful login, "
                       "optionally from a template"),
                   [=](const CString& sLine) { CreateUsersCommand(sLine); });
        AddCommand("SetSASLNetwork", t_d("<network name>"),
                   t_d("Set the network to configure the SASL module for."),
                   [=](const CString& sLine) { SetSASLNetworkCommand(sLine); });
        AddCommand("SetSASL",
                   t_d("no|yes [<mechanism> [<username> <password>]]|reset"),
                   t_d("Configure the mechanism used by the SASL module and any"
                       " necessary authentication credentials"),
                   [=](const CString& sLine) { SetSASLCommand(sLine); });
        AddCommand("SetWEBIRC",
                   t_d("no|yes [<gateway> <password> <hostname>]|reset"),
                   t_d("Configure the gateway, password and the hostname "
                       "suffix used for WEBIRC connections."),
                   [=](const CString& sLine) { SetWEBIRCCommand(sLine); });
        AddCommand("SetUserSalt", t_d("<salt>"),
                   t_d("Configure the salt used when hashing usernames. "),
                   [=](const CString& sLine) { SetUserSaltCommand(sLine); });
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
            } else if (it->Equals("webirc")) {
                m_bWEBIRC = true;
            } else if (it->Equals("impersonation")) {
                m_bSaslImpersonation = true;
            } else {
                CUtils::PrintError(
                    t_f("Ignoring invalid SASL pwcheck method: {1}")(*it));
                sMessage = t_s("Ignored invalid SASL pwcheck method");
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
        const CString& sUsername = Auth->GetUsername().AsLower();
        const CString& sPassword = Auth->GetPassword();
        CUser* pUser(CZNC::Get().FindUser(sUsername));
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
                   sasl_checkpass(sasl_conn, sUsername.c_str(),
                                  sUsername.size(), sPassword.c_str(),
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
                pUser = new CUser(sUsername);

                if (ShouldCloneUser()) {
                    CUser* pBaseUser = CZNC::Get().FindUser(CloneUser());

                    if (!pBaseUser) {
                        DEBUG("saslauth: Clone User [" << CloneUser()
                                                       << "] User not found");
                        delete pUser;
                        pUser = nullptr;
                    }

                    if (pUser && !pUser->Clone(*pBaseUser, sErr, true)) {
                        DEBUG("saslauth: Clone User [" << CloneUser()
                                                       << "] failed: " << sErr);
                        delete pUser;
                        pUser = nullptr;
                    }

                    CString sUsernameAsTyped = Auth->GetUsername();

                    pUser->SetNick(sUsernameAsTyped);
                    pUser->SetAltNick(sUsernameAsTyped + "_");
                    pUser->SetIdent(sUsernameAsTyped);
                    pUser->SetRealName(sUsernameAsTyped);

                    if (m_bSaslImpersonation) {
                        CIRCNetwork* pNetwork =
                            pUser->FindNetwork(GetNV("network_name"));

                        if (!pNetwork) {
                            DEBUG("saslauth: Find network ["
                                  << GetNV("network_name")
                                  << "] failed: " << sErr);
                            delete pUser;
                            pUser = nullptr;
                        }

                        if (pNetwork->GetModules().LoadModule(
                                "sasl", "", CModInfo::NetworkModule, pUser,
                                pNetwork, sErr)) {
                            CModule* pModule =
                                pNetwork->GetModules().FindModule("sasl");
                            pModule->SetNV("impersonation", "yes");
                            pModule->SetNV("username", GetNV("sasl_username"));
                            pModule->SetNV("password", GetNV("sasl_password"));
                            pModule->SetNV("mechanisms",
                                           GetNV("sasl_mechanism"));
                            pModule->SetNV("require_auth", "yes");
                        } else {
                            DEBUG(
                                "saslauth: Load network module [sasl] failed: "
                                << sErr);
                            delete pUser;
                            pUser = nullptr;
                        }
                    }
                }

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
            }

            if (pUser) {
                Auth->AcceptLogin(*pUser);
                return HALT;
            }
        }

        return CONTINUE;
    }

    EModRet OnIRCRegistration(CString& sPass, CString& sNick, CString& sIdent,
                              CString& sRealname) override {
        if (m_bWEBIRC) {
            CUser* pUser = GetUser();
            CIRCNetwork* pNetwork = GetNetwork();

            if (pUser && !pNetwork->GetName().CaseCmp(GetNV("network_name"))) {
                std::ostringstream sWebIRCMsg;
                CString sUsername = pUser->GetUsername();
                CMD5 md5sum(sUsername + GetNV("user_salt"));
                uint8* hashBytes = downsample(md5sum.GetHash());
                uint hashInts[3] = {hashBytes[0], hashBytes[1], hashBytes[2]};

                sWebIRCMsg << "WEBIRC " << GetNV("webirc_password") << " "
                           << GetNV("webirc_gateway") << " " << sUsername << "."
                           << GetNV("webirc_host_suffix") << " 255."
                           << hashInts[0] << "." << hashInts[1] << "."
                           << hashInts[2];

                PutIRC(sWebIRCMsg.str());
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

    void SetSASLNetworkCommand(const CString& sLine) {
        CString sNetwork = sLine.Token(1);
        if (!sNetwork.empty()) {
            SetNV("network_name", sNetwork);
            PutModule(t_s("We will configure the [" + sNetwork +
                          "] network for SASL."));
        } else {
            PutModule(
                t_s("Usage: SetSASLNetwork afternet, SetSASLNetwork libera, "
                    "SetSASLNetwork <network>"));
        }
    }

    void SetSASLCommand(const CString& sLine) {
        CString sEnable = sLine.Token(1);

        if (sEnable == "no") {
            m_bSaslImpersonation = false;
        } else if (sEnable == "yes") {
            if (!sLine.Token(2).empty())
                SetNV("sasl_mechanism", sLine.Token(2));
            if (!sLine.Token(3).empty()) SetNV("sasl_username", sLine.Token(3));
            if (!sLine.Token(4).empty()) SetNV("sasl_password", sLine.Token(4));

            m_bSaslImpersonation = true;

            PutModule(t_f("SASL mechanism has been set to [{1}]")(
                GetNV("sasl_mechanism")));
            PutModule(t_f("SASL username has been set to [{1}]")(
                GetNV("sasl_username")));
            PutModule(t_f("SASL password has been set to [{1}]")(
                GetNV("sasl_password")));
        } else if (sEnable == "reset") {
            m_bSaslImpersonation = false;
            SetNV("sasl_mechanism", "");
            SetNV("sasl_username", "");
            SetNV("sasl_password", "");
        } else {
            if (m_bSaslImpersonation) {
                CString sMechanism = GetNV("sasl_mechanism");
                CString sUsername = GetNV("sasl_username");
                CString sPassword = GetNV("sasl_password");

                if (sMechanism.empty()) {
                    PutModule(t_s("SASL mechanism is currently not set"));
                } else {
                    PutModule(t_f("SASL mechanism is currently set to '{1}'")(
                        sMechanism));
                }
                if (sUsername.empty()) {
                    PutModule(t_s("SASL username is currently not set"));
                } else {
                    PutModule(t_f("SASL username is currently set to '{1}'")(
                        sUsername));
                }
                if (sPassword.empty()) {
                    PutModule(t_s("SASL password was not supplied"));
                } else {
                    PutModule(t_s("Password was supplied"));
                }
            } else {
                PutModule(
                    t_s("Usage: SetSASL yes EXTERNAL, SetSASL yes PLAIN "
                        "zncuser zncpassword, SetSASL no, SetSASL reset"));
            }
        }
    }

    void SetWEBIRCCommand(const CString& sLine) {
        CString sEnable = sLine.Token(1);

        if (sEnable == "no") {
            m_bWEBIRC = false;
        } else if (sEnable == "yes") {
            if (!sLine.Token(2).empty())
                SetNV("webirc_gateway", sLine.Token(2));
            if (!sLine.Token(3).empty())
                SetNV("webirc_password", sLine.Token(3));
            if (!sLine.Token(4).empty())
                SetNV("webirc_host_suffix", sLine.Token(4));

            m_bWEBIRC = true;

            PutModule(t_f("WEBIRC gateway has been set to [{1}]")(
                GetNV("webirc_gateway")));
            PutModule(t_f("WEBIRC password has been set to [{1}]")(
                GetNV("webirc_password")));
            PutModule(t_f("WEBIRC hostname suffix has been set to [{1}]")(
                GetNV("webirc_host_suffix")));
        } else if (sEnable == "reset") {
            m_bWEBIRC = false;
            SetNV("webirc_gateway", "");
            SetNV("webirc_password", "");
            SetNV("webirc_host_suffix", "");
        } else {
            if (m_bWEBIRC) {
                CString sGateway = GetNV("webirc_gateway");
                CString sPassword = GetNV("webirc_password");
                CString sHostSuffix = GetNV("webirc_host_suffix");

                if (sGateway.empty()) {
                    PutModule(t_s("WEBIRC gateway is currently not set"));
                } else {
                    PutModule(t_f("WEBIRC gateway is currently set to '{1}'")(
                        sGateway));
                }
                if (sPassword.empty()) {
                    PutModule(t_s("WEBIRC password was not supplied"));
                } else {
                    PutModule(t_s("WEBIRC password was supplied"));
                }
                if (sHostSuffix.empty()) {
                    PutModule(
                        t_s("WEBIRC hostname suffix is currently not set"));
                } else {
                    PutModule(
                        t_f("WEBIRC hostname suffix is currently set to '{1}'")(
                            sHostSuffix));
                }
            } else {
                PutModule(
                    t_s("Usage: SetWEBIRC yes zncgateway zncpassword "
                        "Users.AfterNET.Org, SetWEBIRC no, SetWEBIRC reset"));
            }
        }
    }

    void SetUserSaltCommand(const CString& sLine) {
        CString sSalt = sLine.Token(1);
        if (!sSalt.empty()) {
            SetNV("user_salt", sSalt);
            PutModule(
                t_s("We will use [" + sSalt + "] to salt the username hash."));
        } else {
            PutModule(t_s("Usage: SetUserSalt <salt>"));
        }
    }

    bool CreateUser() const { return GetNV("CreateUser").ToBool(); }

    CString CloneUser() const { return GetNV("CloneUser"); }

    bool ShouldCloneUser() { return !GetNV("CloneUser").empty(); }

  protected:
    TCacheMap<CString> m_Cache;

    sasl_callback_t m_cbs[2];
    CString m_sMethod;

    bool m_bWEBIRC;
    bool m_bSaslImpersonation;

    static int getopt(void* context, const char* plugin_name,
                      const char* option, const char** result, unsigned* len) {
        if (CString(option).Equals("pwcheck_method")) {
            *result = ((CSASLAuthMod*)context)->GetMethod().c_str();
            return SASL_OK;
        }

        return SASL_CONTINUE;
    }

    static inline uint8* downsample(uint8 (&i)[16]) {
        uint8* r = new uint8[3]{(uint8)(i[0] ^ i[1] ^ i[2] ^ i[3] ^ i[4]),
                                (uint8)(i[5] ^ i[6] ^ i[7] ^ i[8] ^ i[9]),
                                (uint8)(i[10] ^ i[11] ^ i[12] ^ i[13] ^ i[15])};
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
