package com.bsep.pki_system.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterCADTO {
    private String name;
    private String surname;
    private String email;
    private String organization;

    public RegisterCADTO() {}
}
