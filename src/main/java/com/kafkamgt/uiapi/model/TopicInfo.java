package com.kafkamgt.uiapi.model;

import lombok.Data;

import java.util.List;

@Data
public class TopicInfo {
    private Integer topicid;
    private String sequence;
    private String totalNoPages;
    private String currentPage;
    private List<String> allPageNos;
    private String topicName;
    private Integer noOfPartitions;
    private String description;
    private String documentation;
    private String noOfReplcias;
    private String teamname;
    private String cluster;
    private String clusterId;
    private List<String> environmentsList;
    private boolean showEditTopic;
    private boolean showDeleteTopic;
    private boolean topicDeletable;
}
