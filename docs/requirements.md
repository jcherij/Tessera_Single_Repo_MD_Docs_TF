# Tessera — Requirements

Owner: Payments Engineering
Version: 1.0, October 2026

## Purpose

Meridian Capital collects advisory fees and subscription payments by card. Tessera replaces card numbers with tokens so that the client portal, the billing service and everything downstream of them only ever handle tokens. The card number is needed again only when the billing service submits a charge to the acquirer.

## Compliance

Tessera stores and processes card numbers and must be compliant with PCI DSS.

## Callers

Two systems call Tessera.

The client portal tokenizes a card when a client adds or updates a payment method. It never needs the card number back and must not be able to detokenize.

The billing service tokenizes cards that the operations team enters on a client's behalf, and detokenizes during the monthly billing run to submit charges.

No other system calls Tessera.

## Functional requirements

1. Tokenize accepts a card number and returns a token and the last four digits of the card.
2. Detokenize accepts a token and returns the card number.
3. Tokens are random strings prefixed with `tok_` and cannot be derived from the card number.
4. Tokenizing the same card twice produces two different tokens. Deduplication is not required.
5. Card numbers that fail format or Luhn validation are rejected.
6. Detokenizing an unknown or expired token returns not found.

## Data retention

A token and the card number behind it are kept for 365 days from creation and then deleted automatically. This covers one annual subscription cycle. A client who wants a card removed earlier raises it with Client Services, and Payments Engineering deletes the record manually.

## Volume

Normal traffic is under 5 requests per second. The monthly billing run detokenizes about 8,000 cards over two hours. The API must handle 50 requests per second sustained with bursts to 100, and reject traffic above that rather than queue it. If the billing run is rejected or fails, it retries the next business day.

## Deployment

Tessera runs on AWS in us-east-1 only, with no copies of card data in other regions. There is a single production deployment in the Payments AWS account. It uses managed serverless services only, with no EC2 instances, containers or Kubernetes.

All resources carry the tags Application (`tessera`), Environment, Owner (`payments-engineering`), DataClassification (`cardholder-data`) and PCIScope (`cde`).

## Alerting

Security Engineering is alerted through its existing SNS topic when the API rejects more than 25 requests in five minutes.

## Contacts

Application owner: Payments Engineering lead
Security escalation: Security Engineering
Compliance point of contact: Compliance Engineering
