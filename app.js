'use strict';

require('dotenv').config();
const bodyParser = require('body-parser'),
    crypto = require('crypto'),
    express = require('express'),
    https = require('https'),
    request = require('request'),
    fs = require('fs'),
    mongoose = require('mongoose'),
    mongoosePaginate = require('mongoose-paginate');


// Origin
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN;
const SERVER_URL = process.env.SERVER_URL;

// Facebook
const APP_SECRET = process.env.FB_APP_SECRET;
const VALIDATION_TOKEN = process.env.FB_VALIDATE_TOKEN;
const PAGE_ACCESS_TOKEN = process.env.FB_PAGE_ACCESS_TOKEN;

// Line
const LINE_ACCESS_TOKEN = process.env.LINE_ACCESS_TOKEN;
const LINE_CHANNEL_SECRET = process.env.LINE_CHANNEL_SECRET;


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
var messageSchema = mongoose.Schema({
    sender_id: String,
    recipient_id: String,
    type: String,
    message_id: String,
    message_text: String,
    attachments: Array,
    created: {type: Date, default: Date.now},
}).plugin(mongoosePaginate);

var recipientSchema = mongoose.Schema({
    recipient_id: {type: String, unique: true},
    name: String,
    type: String,
    last_message: {type: Date, default: Date.now}
}).plugin(mongoosePaginate);

var Message = mongoose.model('messages', messageSchema);
var Recipient = mongoose.model('recipients', recipientSchema);

mongoose.Promise = require('bluebird');
mongoose.connect(process.env.MONGO_CONNECTION_STRING, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
    useCreateIndex: true
}, function (err) {
    if (err) {
        throw err;
    }

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
        //Update Status / Assigned to
        socket.on('updateAssignedStatus', function (recipientID, data) {
            io.emit('updateAssignedStatus', recipientID, data);
        })
    });

    /**
     * Line Webhook
     */

    app.post('/line-webhook', function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }
        var data = req.body;
        data.events.forEach(function (entry) {
            if (entry.type === 'message') {
                receivedLineMessage(entry);
            }
        });
        res.sendStatus(200);
    });

    app.post('/api/conversations', async function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }

        const resPerPage = parseInt(req.query.limit) || 15;
        const page = parseInt(req.query.page) || 1;
        try {
            let output = [];
            if (req.query.recipient) {
                const recipients = await Recipient.find({recipient_id: req.query.recipient}).limit(1);
                const count = await Recipient.find({recipient_id : req.query.recipient}).countDocuments();
            } else {
                const recipients = await Recipient.find()
                    .sort('-last_message')
                    .skip((resPerPage * page) - resPerPage)
                    .limit(resPerPage);
                const count = await Recipient.estimatedDocumentCount();
            }


            const max = Math.ceil(count / resPerPage);

            for (const recipient of recipients) {
                let msg = await Message.findOne({recipient_id: recipient.recipient_id}).sort('-created');
                let message = {};
                if (msg) {
                    message = {
                        type: msg.type,
                        text: msg.type === 'text' ? msg.message_text : '('+msg.type+')',
                        created: msg.created
                    }
                }
                output.push({
                    id: recipient.recipient_id,
                    updated_time: recipient.last_message,
                    type: recipient.type,
                    message: message
                });
            }

            res.json({
                data: output,
                next: (page + 1) <= max ? (page + 1) : '',
            });
        } catch (err) {
            throw new Error(err);
        }
    });

    app.post('/api/messages', async function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }

        const resPerPage = parseInt(req.query.limit) || 15;
        const page = parseInt(req.query.page) || 1;
        const recipientId = req.query.recipient;

        try {
            const messages = await Message.find({recipient_id : recipientId})
                .sort('-created')
                .skip((resPerPage * page) - resPerPage)
                .limit(resPerPage);
            const count = await Message.find({recipient_id : recipientId}).countDocuments();
            const max = Math.ceil(count / resPerPage);

            res.json({
                data: messages,
                next: (page + 1) <= max ? (page + 1) : '',
            });
        } catch (err) {
            throw new Error(err);
        }
    })
});

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function (req, res) {
    if (!res.signature_matched) {
        return res.sendStatus(403);
    }
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
    if (!res.signature_matched) {
        return res.sendStatus(403);
    }

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
                    console.log('Received Delivery event');
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
    //verify Facebook
    if (req.headers["x-hub-signature"]) {
        let signature = req.headers["x-hub-signature"];
        var elements = signature.split('=');
        var method = elements[0];
        var signatureHash = elements[1];

        var expectedHash = crypto.createHmac('sha1', APP_SECRET).update(buf).digest('hex');
        if (signatureHash === expectedHash) {
            res.signature_matched = true;
        }
    }
    //verify Line
    else if(req.headers["x-line-signature"]) {
        let signature = req.headers["x-line-signature"];
        let expectedHash = crypto.createHmac('SHA256', LINE_CHANNEL_SECRET).update(buf).digest('base64');
        if (signature === expectedHash) {
            res.signature_matched = true;
        }
    }
    //verify CRM
    else if(req.headers["x-crm-signature"]) {
        let signature = req.headers["x-crm-signature"];
        let expectedHash = crypto.createHmac('SHA256', 'arzqvfom4121xv9vidfp').update(buf).digest('base64');

        if (signature === expectedHash) {
            res.signature_matched = true;
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
    retrieveMessageInfo(message.mid, senderID, false);
}

function retrieveMessageInfo(id, recipientID, owner) {
    Recipient.findOneAndUpdate(
        {recipient_id: recipientID},
        {
            type: 'Facebook',
            last_message: new Date(),
        },
        {upsert: true, new: true, setDefaultsOnInsert: true},
        function (error) {
            if (!error) {
                request({
                    uri: 'https://graph.facebook.com/' + id + '?fields=from,message,attachments,sticker,created_time',
                    qs: {access_token: PAGE_ACCESS_TOKEN},
                    method: 'GET'
                }, function (error, response, body) {
                    if (!error && response.statusCode === 200) {
                        let data = JSON.parse(body);
                        let msg;
                        if (data.sticker) {
                            msg = new Message({
                                sender_id: owner ? 'owner' : recipientID,
                                recipient_id: recipientID,
                                type: 'sticker',
                                message_id: data.id,
                                message_text: data.sticker,
                                created: data.created_time,
                            });
                        } else if (data.attachments) {
                            let attachments = [];
                            data.attachments.data.forEach(function (i) {
                                if (i.image_data) {
                                    attachments.push({type: 'image', url: i.image_data.url, preview_url: i.image_data.preview_url});
                                } else {
                                    attachments.push({type: 'file', url: i.file_url, name: i.name});
                                }
                            });
                            msg = new Message({
                                sender_id: owner ? 'owner' : recipientID,
                                recipient_id: recipientID,
                                type: 'attachment',
                                message_id: data.id,
                                attachments: attachments,
                                created: data.created_time,
                            });
                        } else {
                            msg = new Message({
                                sender_id: owner ? 'owner' : recipientID,
                                recipient_id: recipientID,
                                type: 'text',
                                message_id: data.id,
                                message_text: data.message,
                                created: data.created_time,
                            });
                        }
                        //Save Facebook Message
                        msg.save(function (err, data) {
                            if (!err) {
                                io.emit('receivedMessage', recipientID, body, owner);
                            }
                        });
                    } else {
                        console.error("Failed retrieving Message info", response.statusCode, response.statusMessage, body.error);
                    }
                });
            }
        });
}

function sendMarkSeen(recipientID) {
    console.log("Mark last message as seen", recipientID);
    var messageData = {
        messaging_type: "MESSAGE_TAG",
        tag: "ISSUE_RESOLUTION",
        recipient: {
            id: recipientID
        },
        sender_action: "mark_seen"
    };

    callSendAPI(messageData);
}

function sendAttachment(recipientID, url, type) {
    if (typeof type === 'undefined') {
        type = 'file';
    }
    var messageData = {
        messaging_type: "MESSAGE_TAG",
        tag: "ISSUE_RESOLUTION",
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
        messaging_type: "MESSAGE_TAG",
        tag: "ISSUE_RESOLUTION",
        recipient: {
            id: recipientID
        },
        message: {
            text: messageText
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

/* ****************LINE EVENT******************* */
function receivedLineMessage(event) {
    Recipient.findOneAndUpdate(
        {recipient_id: event.source.userId},
        {
            type: 'Line',
            last_message: new Date(),
        },
        {upsert: true, new: true, setDefaultsOnInsert: true },
        function (error) {
            if (!error) {
                switch (event.message.type) {
                    case 'text':
                        let msg = new Message({
                            sender_id: event.source.userId,
                            recipient_id: event.source.userId,
                            type: 'text',
                            message_id: event.message.id,
                            message_text: event.message.text
                        });
                        msg.save(function (err, data) {
                            if (!err) {
                                io.emit('receivedMessage', event.source.userId, JSON.stringify({}), false);
                            }
                        });
                        break;
                    case 'image':
                        request({
                            url: 'https://api-data.line.me/v2/bot/message/'+event.message.id+'/content',
                            method: 'GET',
                            headers: {
                                'Authorization' : 'Bearer ' + LINE_ACCESS_TOKEN
                            },
                            encoding: null
                        }, function (error, response, body) {
                            if (!error && response.statusCode === 200) {
                                let dir = './public/uploads';
                                if (!fs.existsSync(dir)){
                                    fs.mkdirSync(dir);
                                }
                                fs.writeFileSync(dir + '/' + event.message.id + '.png', Buffer.from(body));

                                let msg = new Message({
                                    sender_id: event.source.userId,
                                    recipient_id: event.source.userId,
                                    type: 'attachment',
                                    message_id: event.message.id,
                                    attachments: [
                                        {
                                            type: 'image',
                                            url: SERVER_URL + '/uploads/' + event.message.id + '.png',
                                            preview_url: SERVER_URL + '/uploads/' + event.message.id + '.png',
                                        }
                                    ]
                                });

                                msg.save(function (err, data) {
                                    if (!err) {
                                        io.emit('receivedMessage', event.source.userId, JSON.stringify({}), false);
                                    }
                                });
                            }
                        });
                        break;
                    default:
                        console.log('----Received a Line message: This file type ' + event.message.type + ' does not support yet.')
                }
            } else {
                console.log('------error recipient------');
                console.log(error);
                console.log('------end error recipient------');
            }
        });
}
/* ***************END LINE EVENT**************** */
module.exports = app;
