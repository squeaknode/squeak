# How the Squeak Protocol Works

The Squeak protocol attempts to solve the problem of decentralized social media by allowing users to share content in exchange for Bitcoin payments.

This document describes the challenges and how the Squeak protocol solves them with cryptography.

## The problem of incentives in a decentralized social network
There have been many attempts at creating a decentralized protocol for social media. Almost all of them rely on some kind of relay in the network, that accepts posts from users and makes them available to other users.

### Existing protocols

* [Mastodon](https://github.com/mastodon/mastodon) uses a federation model, where the owner of the instance has the power to ban users from their instance.
* [Nostr](https://github.com/fiatjaf/nostr) uses interchangeable relay servers, so no single relay server has the power to ban or censor someone.

### Reliance on relays

These protocols have one major problem, which is that they rely on hubs or relays for the network to work. There is no incentive for someone to host a Mastodon instance or Nostr relay, aside from altruism. A Nostr relay could charge some amount of money for each post that a user uploads, but there is no guarantee that the relay will actually honor their commitment and share the post with other clients. They could just take the money and throw away the post.

In both cases, you are relying on the honesty or generosity of the instance/relay owner to provide a service to the network.

### Pull is better than push

Rather than requiring payment for a client to push content to a relay, a better approach is to require payment when a client pulls content. If a relay receives a payment every time a post is downloaded, then the relay owner has an incentive to host as much content as possible to maximize profit.

## Trustless payments for content in an adversarial environment
The Squeak protocol aims to solve this problem by creating a "flat" network, where every node can connect to every other node, and there is no distinction between clients and relays. Every node can pull content from every other node, and every node follows the same protocol rules.

### Payments must be trustless

In order for this type of flat network to work, it must be possible for payments between nodes to work trustlessly. When a user makes a payment to another node to get a specific piece of content, they must have a guarantee they will get what they pay for.

Without the ability to buy content trustlessly, a reputation system will be necessary, which will make everything more inefficient.

## How trustless payments work
The Squeak protocol uses primitives from elliptic curve cryptography to do trustless Bitcoin payments over Lightning.

### Selling decryption keys over Lightning

The basic idea for how content is sold is as follows:

* Alice has a piece of content she wants to sell.
* Alice generates a scalar value `s1` to use as an encryption/decryption key, and encrypts the content.
* Alice calculates the point `p1` on an elliptic curve `G` by calculating `p1 = s1*G`.
* Alice publishes `p1` for anyone interested in buying the content.
* Bob downloads the encrypted content, and requests an invoice to unlock the content.
* Alice generates a new scalar value `s2`, and creates a *PTLC* Lightning invoice with `s1 + s2` as the preimage.
* Alice sends Bob `s2` and the Lightning invoice as a payment request string.
* Bob decodes the payment request string to get the payment point of the invoice, call it `p3`.
* Bob calculates `s2*G`. If it is equeal to `p3 - p1`, than Bob knows that the invoice is valid.
* Bob pays the Lightning invoice, and gets the value of `s1` as the preimage, and decrypts the content.

If Alice tries to give Bob an invalid invoice, Bob will know. And then he will not pay the invoice.


## Connect to other nodes
After you have created some squeaks, you may be wondering if anyone else can read them. Other users will only be able to download your squeaks if their node is connected to your node (or if they connect to another node that already has copies of your squeaks).

You can establish connections to other nodes in two ways:
1) open a connection to another node using its external address
2) share your node's external address and let other nodes connect to you

Once a connection is established, it doesn't matter which node started the connection, inbound and outbound connections are treated the same.

#### Make an outbound connection
If you know the external address of another squeaknode, you can connect to it directly:

- Go to the "Peers" page
- Click on the "Connect Peer" button
- Enter the external address host in the input form
- Enter the external address port in the input form, if it is anything other than the default (8555)
- Check the "Use Tor" toggle if the address is an onion address
- Submit the dialog form

After a few seconds, if the connection is successful, you should see the newly connected peer in the list of connected peers.

![Screenshot from 2021-11-11 04-24-52]({{ site.baseurl }}/images/268bc4e9f8e10d26e1f6d2516c3d349b256eddfb.png)

#### Accept inbound connections
You can also share your external address, and allow other nodes to make connections to you.

- Go to the "Peers" page
- Click on the "Show External Address" button
- Copy the content of the displayed address and share it wherever you want

Now anyone who knows this external address can use it to make a connection from their squeaknode to yours.

![Screenshot from 2021-11-11 04-31-09]({{ site.baseurl }}/images/6f3fa0563c88917bf4f48522225893e5c1135030.png)

## Download Squeaks from other users
Now that you have some peer connections open, you can begin to download squeaks from other users onto your timeline.

The squeaknode timeline only shows squeaks from profiles that you are following. You can begin to follow profiles by adding contacts.

- Ask a friend (who is running squeaknode) to share with you the address of their signing profile
- Go to the "Profiles" page
- Click on the "Add Contact" button
- Enter the name of the person
- Enter the address that was provided
- Submit the form to create the new contact profile

![Screenshot from 2021-11-11 04-43-20]({{ site.baseurl }}/images/b02a93fb2c516c043f645f72ed87ef44fb445a5a.png)

After the contact profile is created, your squeaknode will begin to download squeaks from all of your connected peers that match were authored by that profile. If you go to the "Timeline" page, you should see the squeaks in the timeline, if any were downloaded.

## Buying squeaks
Now you have some squeaks from other users visible in your timeline, but they are locked, so you can't read them.

![Screenshot from 2021-11-11 04-49-13]({{ site.baseurl }}/images/2e1de521f24d4e60a43bb273ffd7242c02169979.png)

You unlock squeaks by making Lightning payments to the peers that are selling them.

- Click on the squeak that you want to unlock
- Click on the "Buy To Unlock" button in the middle of the squeak
- When the dialog opens, select one of the offers from the selection
- Check the price of the squeak, and if you agree to pay that amount, click the "Buy Squeak" button
- Wait a few seconds for the Lightning payment to complete, and then the squeak should unlock

![Screenshot from 2021-11-11 04-52-34]({{ site.baseurl }}/images/e9b0aa6079af9788e680dcd94939feec837b1ef3.png)

Now you should see the unlocked content of the squeak

![Screenshot from 2021-11-11 04-54-57]({{ site.baseurl }}/images/148406198d39ba350074c2d64837e7a22c8bef66.png)

#### Opening a Lightning channel directly to a seller
Sometimes the lightning payment will fail. This usually happens because:
- You do not have a route to the payee
- You do not have enough liquidity in your route

If you want to open a Lightning channel directly to the seller node, you can do that.

- Click on the "Buy To Unlock" button in the middle of the squeak
- When the dialog opens, select one of the offers from the selection
- Click on the link on the "Lightning Node" section of the offer display to go to the "Lightning Node" page
- Click on the "Connect Peer" button to ensure that your Lightning node is connected to the seller Lightning node.
- Click on the "Open Channel" button to open the "Open Channel" dialog
- Enter whatever amount you want to fund the channel and for the transaction fee and submit.
- Now wait for the Bitcoin transactions to complete for the channel to finish opening.

![Screenshot from 2021-11-11 05-05-10]({{ site.baseurl }}/images/5b19df1dcf5047cbce2e12dc44b05b9c35d6d932.png)

After the channel finishes opening, you should be able to complete the payment without any problems.

## Connect your Twitter account
If you are a Twitter user, you can mirror your tweets automatically to your squeaknode profile.

- Obtain a "bearer token" from Twitter (you have to create a Twitter developer account: https://developer.twitter.com/en/apply-for-access)
- Go to the "Twitter" page in the squeaknode app
- Click the "Set Bearer Token" button and copy the bearer token from your Twitter Developer account
- Click the "Add Twitter Account" button and enter your Twitter handle, and select the signing profile where you want it to be mirrored

After you set your bearer token and add your Twitter handle, your squeaknode will be configured to automatically make new squeaks for any new tweets that are created.

![Screenshot from 2021-11-11 05-10-52]({{ site.baseurl }}/images/2730a2c5e8874a74e70a8ab72879ae2f8989f4b5.png)
![Screenshot from 2021-11-11 05-12-50]({{ site.baseurl }}/images/1c67321847551a6e852d976f1acae3e225e161a7.png)
