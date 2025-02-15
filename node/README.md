# Hyperledger Fabric Gateway Client API for Node


The Fabric Gateway client API allows applications to interact with a Hyperledger Fabric blockchain network. It provides a simple API to submit transactions to a ledger or query the contents of a ledger with minimal code.

The Gateway client API implements the Fabric programming model as described in the [Developing Applications](https://hyperledger-fabric.readthedocs.io/en/latest/developapps/developing_applications.html) chapter of the Fabric documentation.

## How to use

Samples showing how to create a client application that updates and queries the ledger are available for each of the supported programming languages here:

* https://github.com/hyperledger/fabric-gateway/tree/main/samples

## API documentation

The Gateway client API documentation for Node is available here:

* https://hyperledger.github.io/fabric-gateway/main/api/node/

## Installation

Add a dependency to your project's `package.json` file with the command:

```sh
npm install @hyperledger/fabric-gateway
```

## Compatibility

This API requires Fabric 2.4 with a Gateway enabled Peer. Additional compatibility information is available in the documentation:

* https://hyperledger.github.io/fabric-gateway/
