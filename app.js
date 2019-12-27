'use strict';

const bodyParser = require('body-parser'),
    config = require('config'),
    crypto = require('crypto'),
    express = require('express'),
    https = require('https'),
    request = require('request');

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and assets located at this address.
const SERVER_URL = config.get('serverURL');

const ALLOW_ORIGIN = config.get('AllowOrigin');

const LINE_ACCESS_TOKEN = config.get('lineAccessToken');
const LINE_CHANNEL_SECRET = config.get('lineChanelSecret');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL && ALLOW_ORIGIN && LINE_ACCESS_TOKEN && LINE_CHANNEL_SECRET)) {
    console.error("Missing config values");
    process.exit(1);
}

var app = express();
var server = app.listen(5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({verify: verifyRequestSignature}));
app.use(express.static('public'));
app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", ALLOW_ORIGIN);
    res.header("Access-Control-Allow-Headers", "X-Requested-With");
    res.header("Access-Control-Allow-Headers", "Content-Type");
    res.header("Access-Control-Allow-Methods", "PUT, GET, POST, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Credentials", true);
    next();
});
//Socket.io
const io = require('socket.io').listen(server);
io.on('connection', (socket) => {
    console.log('A new Client has just been connected');
    socket.on('disconnect', () => console.log('Client disconnected'));
    //Send message
    socket.on('sendMessage', function (recipientID, messageText) {
        sendTextMessage(recipientID, messageText);
    });
    //Send attachment from url
    socket.on('sendAttachment', function (recipientID, url, type) {
        sendAttachment(recipientID, url, type);
    });
    //Mark as seen
    socket.on('seen', function (recipientID) {
        sendMarkSeen(recipientID);
    });
    //Reset unread
    socket.on('read', function (recipientID) {
        sendMarkRead(recipientID);
    });
    //Update Status / Assigned to
    socket.on('updateAssignedStatus', function (recipientID, data) {
        io.emit('updateAssignedStatus', recipientID, data);
    })
});

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
                } else if (messagingEvent.read) {
                    console.log('Received Read event');
                } else if (messagingEvent.delivery) {
                    console.log('Received Read event');
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

/**
 * Line Webhook
 */

app.post('/line-webhook', function (req, res) {
    var data = req.body;
    console.log('-----');
    console.log(data);
    console.log('post - line');
    console.log('-----');
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
    //verify Facebook
    if (req.headers["x-hub-signature"]) {
        let signature = req.headers["x-hub-signature"];
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
    //verify Line
    else if(req.headers["x-line-signature"]) {
        let signature = req.headers["x-line-signature"];
        let expectedHash = crypto.createHmac('sha1', LINE_CHANNEL_SECRET);

        console.log('--verify--');
        console.log(signature);
        console.log(expectedHash)
        console.log('--end verify--');


    } else {
        console.log('------------');
        console.log(req.headers);
        console.log('------------');
        throw new Error("Couldn't validate the request signature.");
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
    console.log(event);
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfMessage = event.timestamp;
    var message = event.message;

    console.log("Received message from user %d to page %d at %d with message:",
        senderID, recipientID, timeOfMessage);

    retrieveMessageInfo(message.mid, senderID, false);
}

function retrieveMessageInfo(id, recipientID, owner) {
    request({
        uri: 'https://graph.facebook.com/' + id + '?fields=from,message,attachments,sticker,created_time',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'GET'
    }, function (error, response, body) {
        if (!error && response.statusCode === 200) {
            console.log('------');
            console.log('Successfully retrieved Message info');
            console.log('-------');
            io.emit('receivedMessage', recipientID, body, owner);
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

function sendAttachment(recipientID, url, type) {
    if (typeof type === 'undefined') {
        type = 'file';
    }
    var messageData = {
        recipient: {
            id: recipientID
        },
        message: {
            attachment: {
                type: type,
                payload: {
                    url: url
                }
            }
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
                retrieveMessageInfo(messageId, recipientID, true);
            } else {
                console.log("Successfully called Send API for recipient %s", recipientID);
            }
        } else {
            console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
        }
    });
}

module.exports = app;
