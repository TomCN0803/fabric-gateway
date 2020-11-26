/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.stub.StreamObserver;
import org.hyperledger.fabric.gateway.*;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.peer.Chaincode;
import org.hyperledger.fabric.protos.peer.ProposalPackage;

import java.util.List;
import java.util.stream.Collectors;

public class MockGatewayService extends GatewayGrpc.GatewayImplBase {
    @Override
    public void endorse(ProposedTransaction request, StreamObserver<PreparedTransaction> responseObserver) {
        responseObserver.onNext(createMockTransaction(request));
        responseObserver.onCompleted();
    }

    @Override
    public void submit(PreparedTransaction request, StreamObserver<Event> responseObserver) {
        responseObserver.onNext(createMockEvent());
        responseObserver.onNext(createMockEvent());
        responseObserver.onCompleted();
    }

    @Override
    public void evaluate(ProposedTransaction request, StreamObserver<Result> responseObserver) {
        ByteString resultPayload = createMockPayload(request);
        responseObserver.onNext(createMockResult(resultPayload));
        responseObserver.onCompleted();
    }

    private PreparedTransaction createMockTransaction(ProposedTransaction request) {
        ByteString payload = createMockPayload(request);
        Common.Envelope envelope = Common.Envelope.newBuilder()
                .setPayload(payload)
                .setSignature(ByteString.copyFromUtf8("mock signature"))
                .build();
        return PreparedTransaction.newBuilder()
                .setEnvelope(envelope)
                .setResponse(createMockResult(payload))
                .build();
    }

    private Event createMockEvent() {
        return Event.newBuilder()
                .setValue(ByteString.copyFromUtf8("mock event"))
                .build();
    }

    private Result createMockResult(ByteString value) {
        return Result.newBuilder()
                .setValue(value)
                .build();
    }

    private ByteString createMockPayload(ProposedTransaction request) {
        // create a mock payload string by concatenating the chaincode id, tx name and arguments from the request
        try {
            ProposalPackage.Proposal proposal = ProposalPackage.Proposal.parseFrom(request.getProposal().getProposalBytes());
            ProposalPackage.ChaincodeProposalPayload chaincodeProposalPayload = ProposalPackage.ChaincodeProposalPayload.parseFrom(proposal.getPayload());
            Chaincode.ChaincodeInvocationSpec chaincodeInvocationSpec = Chaincode.ChaincodeInvocationSpec.parseFrom(chaincodeProposalPayload.getInput());
            String chaincodeId = chaincodeInvocationSpec.getChaincodeSpec().getChaincodeId().getName();
            List<ByteString> args = chaincodeInvocationSpec.getChaincodeSpec().getInput().getArgsList();
            String payload = chaincodeId + args.stream().map(arg -> arg.toStringUtf8()).collect(Collectors.joining());
            return ByteString.copyFromUtf8(payload);
        } catch (InvalidProtocolBufferException ex) {
            return ByteString.copyFromUtf8(ex.getMessage());
        }
    }
}
