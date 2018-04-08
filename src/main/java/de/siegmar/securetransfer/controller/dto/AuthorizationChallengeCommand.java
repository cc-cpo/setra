package de.siegmar.securetransfer.controller.dto;

import javax.validation.constraints.Max;

public class AuthorizationChallengeCommand {

    @Max(999_999)
    private int challengeNumber1;

    public int getChallengeNumber1() {
        return challengeNumber1;
    }

    public void setChallengeNumber1(final int challengeNumber1) {
        this.challengeNumber1 = challengeNumber1;
    }

}
