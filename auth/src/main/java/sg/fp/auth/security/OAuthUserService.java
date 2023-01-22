package sg.fp.auth.security;

import sg.fp.auth.entity.UserEntity;
import sg.fp.auth.repository.UserRepository;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class OAuthUserService extends DefaultOAuth2UserService {
    @Autowired
    private UserRepository userRepository;

    public OAuthUserService() {super();}

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException{
         // user-info-uri를 이용해 사용자정보 가져오기
        final OAuth2User oAuth2User = super.loadUser(userRequest);

        //사용자 정보 확인용 로그 - 디버그용
        try{
            log.info("OAuth2User attributes {}", new ObjectMapper().writeValueAsString(oAuth2User.getAttributes()));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        final String accountId = (String) oAuth2User.getAttributes().get("login");
        final String authProvider = userRequest.getClientRegistration().getClientName();

        UserEntity userEntity = null;
        //회원가입했던 유저가 아니면 새로 생성
        if(!userRepository.existsByaccountId(accountId)){
            userEntity = UserEntity.builder()
                    .accountId(accountId)
                    .authProvider(authProvider)
                    .build();
            userEntity = userRepository.save(userEntity);
        }

        log.info("Successfully pulled user info accountId {} authProvider {}", accountId, authProvider);

        return new ApplicationOAuth2User(userEntity.uuidToString(userEntity.getId()), oAuth2User.getAttributes());
    }
}
