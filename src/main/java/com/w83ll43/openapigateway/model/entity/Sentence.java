package com.w83ll43.openapigateway.model.entity;

import lombok.Data;

import java.util.Date;

@Data
public class Sentence {

    /**
     * 主键ID
     */
    private Integer id;

    /**
     * 句子UUID
     */
    private String uuid;

    /**
     * 句子
     */
    private String hitokoto;

    /**
     * 类型
     */
    private String type;

    /**
     * 来源
     * from 是 MySQL 的关键字、需要添加反引号
     */
    private String from;

    /**
     * 来自谁
     */
    private String fromWho;

    /**
     * 创建者
     */
    private String creator;

    /**
     * 创建者ID
     */
    private Integer creatorUid;

    /**
     *
     */
    private Integer reviewer;

    /**
     *
     */
    private String commitFrom;

    /**
     * 创建时间
     */
    private Date createdAt;

    /**
     * 句子长度
     */
    private Integer length;

    private static final long serialVersionUID = 1L;
}
