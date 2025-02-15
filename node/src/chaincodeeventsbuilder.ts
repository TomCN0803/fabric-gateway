/*
 * Copyright 2021 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { ChaincodeEventsRequest, ChaincodeEventsRequestImpl } from './chaincodeeventsrequest';
import { GatewayClient } from './client';
import { ChaincodeEventsRequest as ChaincodeEventsRequestProto } from './protos/gateway/gateway_pb';
import { SeekNextCommit, SeekPosition, SeekSpecified } from './protos/orderer/ab_pb';
import { SigningIdentity } from './signingidentity';

/**
 * Options used when requesting chaincode events.
 */
export interface ChaincodeEventsOptions {
    /**
     * Block number at which to start reading chaincode events.
     */
    startBlock?: bigint;
}

export interface ChaincodeEventsBuilderOptions extends ChaincodeEventsOptions {
    client: GatewayClient;
    signingIdentity: SigningIdentity;
    channelName: string;
    chaincodeName: string;
}

export class ChaincodeEventsBuilder {
    readonly #options: Readonly<ChaincodeEventsBuilderOptions>;

    constructor(options: Readonly<ChaincodeEventsBuilderOptions>) {
        this.#options = options;
    }

    build(): ChaincodeEventsRequest {
        return new ChaincodeEventsRequestImpl({
            client: this.#options.client,
            signingIdentity: this.#options.signingIdentity,
            request: this.#newChaincodeEventsRequestProto(),
        });
    }

    #newChaincodeEventsRequestProto(): ChaincodeEventsRequestProto {
        const result = new ChaincodeEventsRequestProto();
        result.setChannelId(this.#options.channelName);
        result.setChaincodeId(this.#options.chaincodeName);
        result.setIdentity(this.#options.signingIdentity.getCreator());
        result.setStartPosition(this.#getStartPosition());

        return result;
    }

    #getStartPosition(): SeekPosition {
        const result = new SeekPosition();

        const startBlock = this.#options.startBlock;
        if (startBlock != undefined) {
            const specified = new SeekSpecified();
            specified.setNumber(Number(startBlock));

            result.setSpecified(specified);

            return result;
        }

        result.setNextCommit(new SeekNextCommit());
        return result;
    }
}
