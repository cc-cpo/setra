package de.siegmar.securetransfer.service;

import javax.annotation.PostConstruct;

import org.springframework.stereotype.Service;

import com.warrenstrange.googleauth.GoogleAuthenticator;

@Service
public class GoogleAuthenticatorOTPService {

    // FIXME move to file
    private static final String STEFAN_SECReT = "KR52HV2U5Z4DWGLJ";

    private final GoogleAuthenticator authenticator = new GoogleAuthenticator();


    @PostConstruct
    public void init() {
    }

    public boolean checkCode(final int verificationCode) {
        final boolean authorized = authenticator.authorize(STEFAN_SECReT, verificationCode);
        return authorized;
    }


}
