package com.jaypal.authapp.helpers;

import java.util.UUID;

public class UserHelper {

    public static UUID parseUUID(String uuid) {
        return UUID.fromString(uuid);
    }
}
