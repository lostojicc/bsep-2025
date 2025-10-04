package com.bsep.pki_system.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CaUserDTO {
    private Long id;
    private String surname;
    private String name;
    private  String email;

    public CaUserDTO(Long id, String name, String surname, String email) {
        this.id = id;
        this.name = name;
        this.surname = surname;
        this.email = email;
    }
}
