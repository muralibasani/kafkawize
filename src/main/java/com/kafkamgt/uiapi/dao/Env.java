package com.kafkamgt.uiapi.dao;


import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;

@ToString
@Getter
@Setter
@Entity
@IdClass(EnvID.class)
@Table(name="kwenv")
public class Env implements Serializable {

    @Id
    @Column(name = "id")
    private String id;

    @Id
    @Column(name = "tenantid")
    private Integer tenantId;

    @Column(name = "envname")
    private String name;

    @Column(name = "stretchcode")
    private String stretchCode;

    @Column(name = "clusterid")
    private Integer clusterId;

    @Column(name = "envtype")
    private String type;

    @Column(name = "otherparams")
    private String otherParams;

    @Column(name = "envexists")
    private String envExists;

    @Column(name = "envstatus")
    private String envStatus;
}
