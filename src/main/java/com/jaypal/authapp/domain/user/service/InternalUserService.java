package com.jaypal.authapp.domain.user.service;

import com.jaypal.authapp.domain.dto.user.UserCreateRequest;
import com.jaypal.authapp.domain.user.entity.User;

public interface InternalUserService {

    User createAndReturnDomainUser(UserCreateRequest request);
}
