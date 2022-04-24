/*
 * Copyright (C) 2014-2022 evilnet
 * Copyright (C) 2014-2022 John Economou
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
 * @class CWebIRC
 * @author John Economou
 * @brief WEBIRC-based host and IP spoofing module for znc.
 */

#include <znc/znc.h>
#include <znc/IRCNetwork.h>
#include <znc/User.h>
#include <znc/MD5.h>

#include <sasl/sasl.h>
#include <sstream>

class CWebIRC : public CModule {
  public:
    MODCONSTRUCTOR(CWebIRC) {
        m_bWebIrcEnabled = false;

        AddHelpCommand();
        AddCommand("Show", "", t_d("Shows current settings"),
                   [=](const CString& sLine) { ShowCommand(sLine); });
        AddCommand("SetCredentials", t_d("gateway password"),
                   t_d("Set the gateway and password for WebIRC"),
                   [=](const CString& sLine) { SetCredentials(sLine);});
        AddCommand("SetHostSuffix", t_d("host-suffix"),
                   t_d("Set the hostname suffix used for WebIRC"),
                   [=](const CString& sLine) { SetHostSuffix(sLine);});
        AddCommand("SetUserSalt", t_d("salt"),
                   t_d("Set the salt used when hashing usernames"),
                   [=](const CString& sLine) { SetUserSalt(sLine);});
        AddCommand("SetNetwork", t_d("network"),
                   t_d("Set the network for which WEBIRC will be attempted"),
                   [=](const CString& sLine) { SetNetwork(sLine);});
    }

    void OnModCommand(const CString& sCommand) override {
        if (GetUser()->IsAdmin()) {
            HandleCommand(sCommand);
        } else {
            PutModule(t_s("Access denied"));
        }
    }

    EModRet OnIRCRegistration(CString& sPass, CString& sNick,
            CString& sIdent, CString& sRealName) override
    {
        if (m_bWebIrcEnabled) {
            CUser* pUser = CModule::GetUser();
            CIRCNetwork* pNetwork = CModule::GetNetwork();
            if (pUser != NULL && !(pNetwork->GetName().CaseCmp(Network()))) {
                std::ostringstream sWebIrcMsg;
                CString sUsername = pUser->GetUserName();
                CMD5 md5(sUsername + UserSalt());
                uint8* hashBytes = downsample(md5.GetHash());
                unsigned int hashInts[3] = { hashBytes[0], hashBytes[1], hashBytes[2] };
                sWebIrcMsg << "WEBIRC " << Password() << " " << Username() << " " << sUsername <<
                "." << HostSuffix() << " 255." << hashInts[0] << "." << hashInts[1] << "." << hashInts[2];
                CModule::PutIRC(sWebIrcMsg.str());
                delete[] hashBytes;
            }
        }

        return CONTINUE;
    }

    void ShowCommand(const CString& sLine) {
        if (!HostSuffix().empty())
            PutModule(t_f("WebIRC hostname is set to [{1}]")(HostSuffix()));
        else 
            PutModule(t_s("WebIRC hostname is not set"));

        if (!Username().empty()) {
            PutModule(t_f("WebIRC username is set to [{1}]")(Username()));
        else
            PutModule(t_s("WebIRC username is not set"));

        if (!Password().empty()) {
            PutModule(t_s("WebIRC password is set"));
        else
            PutModule(t_s("WebIRC password is not set"));

        if (!Network().empty()) {
            PutModule(t_f("WebIRC network is set to [{1}]")(Network()));
        else
            PutModule(t_s("WebIRC network is not set"));

        if (!UserSalt().empty()) {
            PutModule(t_f("WebIRC user salt is set to [{1}]")(UserSalt()));
        else
            PutModule(t_s("WebIRC user salt is not set"));
    }

    void SetCredentials(const CString& sLine) {
        SetNV("username", sLine.Token(1));
        SetNV("password", sLine.Token(2));
        PutModule(t_f("WebIRC Username has been set to [{1}]")(Username()));
        PutModule(t_f("WebIRC Password has been set to [{1}]")(Password()));
    }

    void SetHostSuffix(const CString& sLine) {
        SetNV("hostsuffix", sLine.Token(1));
        PutModule(t_f("WebIRC hostname has been set to [{1}]")(HostSuffix()));
    }

    void SetNetwork(const CString& sLine) {
        SetNV("network", sLine.Token(1));
        PutModule(t_f("Network name used for newly created accounts has been"
                  " set to [{1}]")(Network()));
    }

    void SetUserSalt(const CString& sLine) {
        SetNV("usersalt", sLine.Token(1));
        PutModule(t_f("User salt has been set to [{1}]")(UserSalt()));
    }

    CString HostSuffix() const { return GetNV("hostsuffix"); }

    CString Network() const { return GetNV("network"); }

    CString Password() const { return GetNV("password"); }

    CString Username() const { return GetNV("username"); }

    CString UserSalt() const { return GetNV("usersalt"); }

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
void TModInfo<CWebIRC>(CModInfo& Info) {
    Info.SetWikiPage("webirc");
    Info.SetHasArgs(false);
}

GLOBALMODULEDEFS(
    CWebIRC,
    t_s("Use WEBIRC to spoof users hostnames and IP addresses on a selected network"))
