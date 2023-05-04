package com.w83ll43.openapigateway.model.entity;

import lombok.Data;

import java.io.Serializable;

/**
 * 
 * @TableName joke_text
 */
@Data
public class JokeText implements Serializable {
    /**
     * 文本ID
     */
    private Integer textId;

    /**
     * 文本标题ID
     */
    private Integer textTitleId;

    /**
     * 文本
     */
    private String text;

    private static final long serialVersionUID = 1L;
}