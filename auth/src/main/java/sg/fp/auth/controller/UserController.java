package sg.fp.auth.controller;

import sg.fp.auth.dto.ResponseDTO;
import sg.fp.auth.dto.UserDTO;
import sg.fp.auth.entity.UserEntity;
import sg.fp.auth.security.TokenProvider;
import sg.fp.auth.service.UserService;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@Slf4j
@RestController
@RequestMapping("/auth")
public class UserController {
    @Autowired
    private UserService userService;
    @Autowired
    private TokenProvider tokenProvider;

    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    //1. 회원가입
    @PostMapping("/signup")
    public ResponseEntity<?> resgisterUser(@RequestBody UserDTO userDTO){
        try{//validation
            if(userDTO==null || userDTO.getAccountPw()==null){
                throw new RuntimeException("Invalid Password value.");
            }

            UserEntity user = UserEntity.builder()
                    .email(userDTO.getEmail())
                    .accountId(userDTO.getAccountId())
                    .accountPw(passwordEncoder.encode(userDTO.getAccountPw()))
                    .accountName(userDTO.getAccountName())
                    .build();

            UserEntity registerdUser = userService.create(user);

            UserDTO responseUserDTO = UserDTO.builder()
                    .id(registerdUser.uuidToString(registerdUser.getId()))
                    .accountId(registerdUser.getAccountId())
                    .build();
            return ResponseEntity.ok().body(responseUserDTO);
        }catch(Exception e){
            ResponseDTO responseDTO = ResponseDTO.builder().error(e.getMessage()).build();
            return ResponseEntity.badRequest().body(responseDTO);
        }
    }

    //2. 로그인
    @PostMapping("/signin")
    public ResponseEntity<?> authenticate(@RequestBody UserDTO userDTO){
        UserEntity user = userService.getByCredentials(userDTO.getAccountId(), userDTO.getAccountPw(), passwordEncoder);

        if(user!=null){
            final String token = tokenProvider.create(user);
            final UserDTO responseUserDTO = UserDTO.builder()
                    .accountId(user.getAccountId())
                    .id(user.uuidToString(user.getId()))
                    .token(token)
                    .build();
            return ResponseEntity.ok().body(responseUserDTO);
        } else{
            ResponseDTO responseDTO = ResponseDTO.builder().error("Login failed.").build();
            return ResponseEntity.badRequest().body(responseDTO);
        }
    }

}
