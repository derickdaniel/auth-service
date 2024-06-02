package com.microservice.authservice.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "Roles")
@NoArgsConstructor
@Getter
@Setter
public class Role extends IdBasedEntity implements Serializable {

	private static final long serialVersionUID = -7807581782639596850L;

	@Enumerated(EnumType.STRING)
	@Column(length = 20, unique = true)
	private ERole name;

	public Role() {
	}

	public Role(ERole name) {
		this.name = name;
	}

	public ERole getName() {
		return name;
	}
}
