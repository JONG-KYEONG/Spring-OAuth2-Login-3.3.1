# Spring-OAuth2-Login-3.3.1
Spring 3.3.1 ver. Social OAuth2 Login with Google and github and kakao and Naver
- Spring Boot 3.x.x 버전 & Spring Security 6.x 버전에서 작동합니다.
- 하위 버전은 아래 링크에서 지원합니다.
  - https://github.com/FhRh/Spring-OAuth2-Login

# Manual
- spring_social의 이름을 가진 DB를 구축합니다.
```mysql
mysql> create database spring_social;
```

- application.properties에 발급받은 ID & secret 을 추가하여 사용할 수 있습니다.
```properties
#Google OAuth
spring.security.oauth2.client.registration.google.client-id={client-id}
spring.security.oauth2.client.registration.google.client-secret={client-secret}
spring.security.oauth2.client.registration.google.redirect-uri=http://localhost:8080/oauth2/callback/google
spring.security.oauth2.client.registration.google.scope=email,profile

#Github OAuth
spring.security.oauth2.client.registration.github.client-id={client-id}
spring.security.oauth2.client.registration.github.client-secret={client-secret}
spring.security.oauth2.client.registration.github.redirect-uri=http://localhost:8080/oauth2/callback/github
spring.security.oauth2.client.registration.github.scope=user:email,read:user

#KakaoTalk OAuth
spring.security.oauth2.client.registration.kakao.client-id={client-id}
spring.security.oauth2.client.registration.kakao.client-secret={client-secret}
spring.security.oauth2.client.provider.kakao.authorization-uri=https://kauth.kakao.com/oauth/authorize
spring.security.oauth2.client.registration.kakao.scope=profile_nickname,profile_image,account_email
spring.security.oauth2.client.registration.kakao.client-name=kakao-login
spring.security.oauth2.client.registration.kakao.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.kakao.redirect-uri=http://localhost:8080/oauth2/callback/kakao
spring.security.oauth2.client.registration.kakao.client-authentication-method=client_secret_post
spring.security.oauth2.client.provider.kakao.token-uri=https://kauth.kakao.com/oauth/token
spring.security.oauth2.client.provider.kakao.user-info-uri=https://kapi.kakao.com/v2/user/me
spring.security.oauth2.client.provider.kakao.user-name-attribute=id

#Naver OAuth
spring.security.oauth2.client.registration.naver.client-id={client-id}
spring.security.oauth2.client.registration.naver.client-secret={client-secret}
spring.security.oauth2.client.registration.naver.scope=name, email, profile_image, nickname
spring.security.oauth2.client.registration.naver.client-name=Naver
spring.security.oauth2.client.registration.naver.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.naver.redirect-uri=http://localhost:8080/oauth2/callback/naver
spring.security.oauth2.client.provider.naver.authorization-uri=https://nid.naver.com/oauth2.0/authorize
spring.security.oauth2.client.provider.naver.token-uri=https://nid.naver.com/oauth2.0/token
spring.security.oauth2.client.provider.naver.user-info-uri=https://openapi.naver.com/v1/nid/me
spring.security.oauth2.client.provider.naver.user-name-attribute=response

app.auth.tokenSecret=04ca023b39512e46d0c2cf4b48d5aac61d34302994c87ed4eff225dcf3b0a218739f3897051a057f9b846a69ea2927a587044164b7bae5e1306219d50b588cb1
app.auth.tokenExpirationMsec = 864000000
app.cors.allowedOrigins=http://localhost:3000,http://localhost:8080
app.oauth2.authorizedRedirectUris=http://localhost:3000/oauth2/redirect,myandroidapp://oauth2/redirect,myiosapp://oauth2/redirect
```

# Issue
- Spring Security 6.x 버전에서는 보안 구성 시 람다 표현식 사용을 요구함에 따라 코드 수정하였습니다. 
- Spring Security 6.x 버전에서 KAKAO의 경우 client-authentication-method로 client_secret_post, client_secret_basic, none 만 제공됩니다
  - POST -> client_secret_post 로 수정하였습니다.

# Caution  
- 이 코드는 백엔드 코드로써 동작합니다.
  - 따라서, 전체 과정을 테스트 하기 위해서는 프론트 코드를 필요로 합니다.
  - 같은 장치에서 서버를 돌릴때, 프론트에서 접근 방식은 다음과 같습니다.
    -  로그인시 : http://localhost:8080/oauth2/authorization/{registrationId}?redirect_url=http://localhost:3000/oauth2/redirect
    -  리다이렉션시 jwtToken을 저장하는 로직이 필요합니다.
