package com.kafkamgt.uiapi.dao;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;

@Getter
@Setter
@Entity
@ToString
@Table(name="kwteams")
@IdClass(TeamID.class)
public class Team implements Serializable {

    @Id
    @Column(name = "teamid")
    private Integer teamId;

    @Column(name = "team")
    private String teamname;

    @Id
    @Column(name = "tenantid")
    private Integer tenantId;

    @Column(name = "teammail")
    private String teammail;

    @Column(name = "app")
    private String app;

    @Column(name = "teamphone")
    private String teamphone;

    @Column(name = "contactperson")
    private String contactperson;

    @Column(name = "requesttopicsenvs")
    private String requestTopicsEnvs;

    @Column(name = "restrictionsobj")
    private String restrictionsObj;

    @Column(name = "otherparams")
    private String otherParams;
}
