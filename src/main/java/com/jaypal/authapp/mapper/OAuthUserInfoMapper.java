package com.jaypal.authapp.mapper;

import com.jaypal.authapp.infrastructure.oauth.model.ValidatedOAuthUserInfo;

import java.util.Map;

public interface OAuthUserInfoMapper {

    ValidatedOAuthUserInfo map(Map<String, Object> attributes);
}
