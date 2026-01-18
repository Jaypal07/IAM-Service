package com.jaypal.authapp.domain.mapper;

import com.jaypal.authapp.domain.infrastructure.oauth.model.ValidatedOAuthUserInfo;

import java.util.Map;

public interface OAuthUserInfoMapper {

    ValidatedOAuthUserInfo map(Map<String, Object> attributes);
}
