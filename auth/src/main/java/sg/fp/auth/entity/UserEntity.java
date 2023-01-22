package sg.fp.auth.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.fasterxml.uuid.Generators;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.util.UUID;

@Data
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name="users", uniqueConstraints = {@UniqueConstraint(columnNames = "accountId")})
public class UserEntity {
    @Id
    @Column(columnDefinition = "BINARY(16)")
    private UUID id;

    @PrePersist /* sequential uuid 생성 */
    public void createId() {
        UUID uuid = Generators.timeBasedGenerator().generate();
        this.id = UUID.fromString(uuidToString(uuid));
    }

    public String uuidToString(UUID uuid){
        String[] uuidArr = uuid.toString().split("-");
        String uuidStr = uuidArr[2]+uuidArr[1]+uuidArr[0]+uuidArr[3]+uuidArr[4];
        StringBuffer sb = new StringBuffer(uuidStr);
        sb.insert(8, "-");
        sb.insert(13, "-");
        sb.insert(18, "-");
        sb.insert(23, "-");
        return sb.toString();
    }

    @Column(nullable = false)
    private String email;
    @Column(nullable = false)
    private String accountId; //계정 아이디

    private String accountPw;    //소셜로그인에선 null이 될 수도 있으므로 가능하게 함. 대신 회원가입할 땐 반드시 입력하게 함.
    private String accountName;     //계정이 등록한 이름
    private String accountRole;    //user or admin
    private String authProvider;    //이후 OAuth에서 사용할 유저 정보 제공자 : github, kakao
}