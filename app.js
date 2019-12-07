/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const
    bodyParser = require('body-parser'),
    config = require('config'),
    crypto = require('crypto'),
    express = require('express'),
    https = require('https'),
    request = require('request');

var app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.json({verify: verifyRequestSignature}));
app.use(express.static('public'));
app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "http://localhost");
    res.header("Access-Control-Allow-Headers", "X-Requested-With");
    res.header("Access-Control-Allow-Headers", "Content-Type");
    res.header("Access-Control-Allow-Methods", "PUT, GET, POST, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Credentials", true);
    next();
});
//Socket.io
var server = app.listen(5000, function(){
    console.log('listening for requests on port 5000,');
});
const io = require('socket.io').listen(server);

//Connect Socket
io.on('connection', (socket) => {
    console.log('A new Client has just been connected');
    socket.on('disconnect', () => console.log('Client disconnected'));
    //Send message
    socket.on('sendMessage', function (recipientID, messageText) {
        sendTextMessage(recipientID, messageText);
    });
    //Mark as seen
    socket.on('seen', function (recipientID) {
        sendMarkSeen(recipientID);
    });
    //Reset unread
    socket.on('read', function (recipientID) {
        sendMarkRead(recipientID);
    })
});




/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
    process.env.MESSENGER_APP_SECRET :
    config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
    (process.env.MESSENGER_VALIDATION_TOKEN) :
    config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
    (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
    config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
    (process.env.SERVER_URL) :
    config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
    console.error("Missing config values");
    process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function (req, res) {
    if (req.query['hub.mode'] === 'subscribe' &&
        req.query['hub.verify_token'] === VALIDATION_TOKEN) {
        console.log("Validating webhook");
        res.status(200).send(req.query['hub.challenge']);
    } else {
        console.error("Failed validation. Make sure the validation tokens match.");
        res.sendStatus(403);
    }
});

/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
    var data = req.body;
    console.log(data);
    // Make sure this is a page subscription
    if (data.object === 'page') {
        data.entry.forEach(function (pageEntry) {
            var pageID = pageEntry.id;
            var timeOfEvent = pageEntry.time;

            // Iterate over each messaging event
            pageEntry.messaging.forEach(function (messagingEvent) {
                if (messagingEvent.optin) {
                    receivedAuthentication(messagingEvent);
                } else if (messagingEvent.message) {
                    receivedMessage(messagingEvent);
                } else {
                    console.log("Webhook received unknown messagingEvent: ", messagingEvent);
                }
            });
        });
        res.sendStatus(200);
    }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function (req, res) {
    var accountLinkingToken = req.query.account_linking_token;
    var redirectURI = req.query.redirect_uri;

    // Authorization Code should be generated per user by the developer. This will
    // be passed to the Account Linking callback.
    var authCode = "1234567890";

    // Redirect users to this URI on successful login
    var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

    res.render('authorize', {
        accountLinkingToken: accountLinkingToken,
        redirectURI: redirectURI,
        redirectURISuccess: redirectURISuccess
    });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
    var signature = req.headers["x-hub-signature"];

    if (!signature) {
        // For testing, let's log an error. In production, you should throw an
        // error.
        console.error("Couldn't validate the signature.");
    } else {
        var elements = signature.split('=');
        var method = elements[0];
        var signatureHash = elements[1];

        var expectedHash = crypto.createHmac('sha1', APP_SECRET)
            .update(buf)
            .digest('hex');

        if (signatureHash !== expectedHash) {
            throw new Error("Couldn't validate the request signature.");
        }
    }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfAuth = event.timestamp;

    // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
    // The developer can set this to an arbitrary value to associate the
    // authentication callback with the 'Send to Messenger' click event. This is
    // a way to do account linking when the user clicks the 'Send to Messenger'
    // plugin.
    var passThroughParam = event.optin.ref;

    console.log("Received authentication for user %d and page %d with pass " +
        "through param '%s' at %d", senderID, recipientID, passThroughParam,
        timeOfAuth);

    // When an authentication is received, we'll send a message back to the sender
    // to let them know it was successful.
    sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 */
function receivedMessage(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfMessage = event.timestamp;
    var message = event.message;

    console.log("Received message from user %d to page %d at %d with message:",
        senderID, recipientID, timeOfMessage);

    retrieveMessageInfo(message.mid, senderID);
}

function retrieveMessageInfo(id, recipientID) {
    request({
        uri: 'https://graph.facebook.com/' + id + '?fields=from,message,created_time',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'GET'
    }, function (error, response, body) {
        if (!error && response.statusCode === 200) {
            console.log('Successfully retrieved Message info');
            console.log(JSON.stringify(body));
            io.emit('receivedMessage', recipientID, body);
        } else {
            console.error("Failed retrieving Message info", response.statusCode, response.statusMessage, body.error);
        }
    });
}

function sendMarkSeen(recipientID) {
    console.log("Mark last message as seen", recipientID);

    var messageData = {
        recipient: {
            id: recipientID
        },
        sender_action: "mark_seen"
    };

    callSendAPI(messageData);
}

function sendMarkRead(recipientID) {
    console.log("Mark last message as seen", recipientID);
    var messageData = {
        sender: {
            id: recipientID
        },
        recipient: {
            id: '165158930691135'
        },
        read: {
            watermark: 15757103850000
        }
    };

    callSendAPI(messageData);

}
/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientID, messageText) {
    var messageData = {
        recipient: {
            id: recipientID
        },
        message: {
            text: messageText,
            metadata: "DEVELOPER_DEFINED_METADATA"
        }
    };

    callSendAPI(messageData);
}
/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
    request({
        uri: 'https://graph.facebook.com/v5.0/me/messages',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'POST',
        json: messageData

    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            var recipientID = body.recipient_id;
            var messageId = body.message_id;
            console.log(body);
            if (messageId) {
                console.log("Successfully sent message with id %s to recipient %s", messageId, recipientID);
                retrieveMessageInfo(messageId, recipientID);
            } else {
                console.log("Successfully called Send API for recipient %s", recipientID);
            }
        } else {
            console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
        }
    });
}

module.exports = app;
