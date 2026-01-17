package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.dto.UserCreateRequest;
import com.jaypal.authapp.user.model.User;

public interface InternalUserService {

    User createAndReturnDomainUser(UserCreateRequest request);
}
