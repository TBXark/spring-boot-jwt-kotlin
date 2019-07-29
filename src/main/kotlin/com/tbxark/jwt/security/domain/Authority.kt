package com.tbxark.jwt.security.domain

import com.fasterxml.jackson.annotation.JsonBackReference
import java.io.Serializable
import javax.persistence.*

@Entity
@Table(name = "AUTHORITY")
data class Authority(@Id
                     @Column(name = "ID")
                     @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "authority_seq")
                     @SequenceGenerator(name = "authority_seq", sequenceName = "authority_seq", allocationSize = 1)
                     var id: Long? = null,

                     @Column(name = "NAME", length = 50)
                     @Enumerated(EnumType.STRING)
                     var name: AuthorityName,

                     @ManyToMany(mappedBy = "authorities", fetch = FetchType.LAZY)
                     @JsonBackReference
                     var users: List<User>? = null): Serializable