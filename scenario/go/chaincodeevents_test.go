/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package scenario

import (
	"context"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

type ChaincodeEventListener struct {
	ctx    context.Context
	cancel context.CancelFunc
	events <-chan *client.ChaincodeEvent
}

func NewChaincodeEventListener(parentCtx context.Context, network *client.Network, chaincodeName string, options ...client.ChaincodeEventsOption) (*ChaincodeEventListener, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	events, err := network.ChaincodeEvents(ctx, chaincodeName, options...)
	if err != nil {
		cancel()
		return nil, err
	}

	listener := &ChaincodeEventListener{
		ctx:    ctx,
		cancel: cancel,
		events: events,
	}
	return listener, nil
}

func (listener *ChaincodeEventListener) ChaincodeEvent() (*client.ChaincodeEvent, error) {
	select {
	case event, ok := <-listener.events:
		if !ok {
			return nil, fmt.Errorf("event channel closed")
		}
		return event, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for event")
	}
}

func (listener *ChaincodeEventListener) Close() {
	listener.cancel()
}
