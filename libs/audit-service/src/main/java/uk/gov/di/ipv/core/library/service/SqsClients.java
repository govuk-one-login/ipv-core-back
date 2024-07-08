package uk.gov.di.ipv.core.library.service;

import software.amazon.awssdk.services.sqs.SqsAsyncClient;
import software.amazon.awssdk.services.sqs.SqsClient;

public record SqsClients(SqsClient sqsClient, SqsAsyncClient sqsAsyncClient) {}
