# IPV Core Back — VPC Migration Map

## What calls Core Back (Inbound)

```mermaid
graph LR
    FRONT[IPV Core Front] -->|Private API GW| CORE[Core Back Lambdas]
    ORCH[Orchestration] -->|External API GW| CORE
    F2F[F2F SQS Queue] -->|cross-account| CORE
    DCMAW[DCMAW Async SQS Queue] -->|cross-account| CORE
```

## What Core Back calls (Outbound)

```mermaid
graph LR
    CORE[Core Back Lambdas] -->|Internet via NAT/Firewall| EXT
    CORE -->|VPC Endpoints| AWS

    subgraph EXT[External Services]
        CRIs[CRIs x13]
        CIMIT[CIMIT API]
        EVCS[EVCS]
        TICF[TICF CRI]
        SIS[SIS]
        AIS[AIS]
    end

    subgraph AWS[AWS Services via VPC Endpoints]
        DDB[DynamoDB]
        SQS[SQS Audit Queue]
        SSM[SSM Params]
        SEC[Secrets Manager]
        KMS[KMS]
        AC[AppConfig]
        S3[S3]
    end
```

## What needs updating in new VPC

| What | Why |
|---|---|
| **ProtectedSubnetIdA/B** | All lambdas run here |
| **VpcId / VpcCidr** | Security group references |
| **LambdaSecurityGroup** | Recreate with same egress/ingress rules |
| **DynamoDB + S3 Gateway Endpoints** | Lambdas access these via prefix lists |
| **Interface Endpoints** (SSM, Secrets Manager, SQS, KMS, AppConfig) | Lambdas access these via endpoint SG |
| **Execute API Gateway Endpoint** | Core Front reaches Private API through this |
| **NAT Gateway + Network Firewall routes** | Outbound HTTPS to CRIs and external APIs |
| **Cross-account SQS access** (F2F, DCMAW) | EventSourceMappings need network path from new VPC |
