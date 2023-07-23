'use strict';

require('dotenv').config();
const bodyParser = require('body-parser'),
    crypto = require('crypto'),
    express = require('express'),
    https = require('https'),
    request = require('request'),
    fs = require('fs'),
    uuid = require('uuid/v4'),
    mongoose = require('mongoose'),
    mongoosePaginate = require('mongoose-paginate'),
    md5 = require('md5'),
    ChatSDK = require('@livechat/chat-sdk');

// Origin
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN;
const SERVER_URL = process.env.SERVER_URL;
const CRM_VALIDATION_KEY = '+91cHDeZoCM7syHhMVMAqI7j4gHHFouz91XpS+TA3XQ=';
const ADMIN_NAME = 'Admin';
const ADMIN_ID = 'owner';
const CONFIG_FILE = 'config.json';
const CONFIG_PORTAL = 'portal.json';
const PORTAL_PREFIX = 'portal_';

// Facebook
const VALIDATION_TOKEN = process.env.FB_VALIDATE_TOKEN;

// LiveChat
const LIVECHAT_CLIENT_ID = process.env.LIVECHAT_CLIENT_ID || '';
const LIVECHAT_CLIENT_SECRET = process.env.LIVECHAT_CLIENT_SECRET || '';
const LIVECHAT_CONFIG_FILE = 'livechat.json';

if (!(VALIDATION_TOKEN && SERVER_URL && ALLOW_ORIGIN)) {
    console.error("Missing config values");
    process.exit(1);
}
const PORT = process.env.PORT || 5000;

var app = express();
var server = app.listen(PORT);
app.set('view engine', 'ejs');
app.use(bodyParser.json({verify: verifyRequestSignature}));
app.use(express.static('public'));
app.use(function (req, res, next) {
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
    message_id: {type: String, default: uuid()},
    message_text: String,
    attachments: Array,
    created: {type: Date, default: Date.now},
}).plugin(mongoosePaginate);

var recipientSchema = mongoose.Schema({
    recipient_id: {type: String, unique: true},
    recipient_name: String,
    channel_id: String,
    type: String,
    email: String,
    live_chat_id: String,
    live_customer_id: String,
    last_message: {type: Date, default: Date.now}
}).plugin(mongoosePaginate);

var portalSessionSchema = mongoose.Schema({
    recipient_id: {type: String, unique: true},
    status: String,
    start_date: {type: Date},
    end_date: {type: Date}
}).plugin(mongoosePaginate);

var greetingLogSchema = mongoose.Schema({
    recipient_id: {type: String, unique: true},
    channel_id: String,
    date: String,
}).plugin(mongoosePaginate);

var businessHourSchema = mongoose.Schema({
    recipient_id: {type: String, unique: true},
    channel_id: String,
    date: String,
}).plugin(mongoosePaginate);

var Message = mongoose.model('messages', messageSchema);
var Recipient = mongoose.model('recipients', recipientSchema);
var PortalSession = mongoose.model('portal_session', portalSessionSchema);
var GreetingLog = mongoose.model('greeting_logs', greetingLogSchema);
var BusinessHourLog = mongoose.model('business_hour_logs', businessHourSchema);
//Live chat
const chatSDK = new ChatSDK({debug: false});

/*
//secret: f6b3d6e6f93d3b2200ad11b3d13db1e9
 https://accounts.livechatinc.com/
 ?response_type=code
 &client_id=37f247f1a7431256bda730b0264f049c
 &redirect_uri=http://localhost:5000/live-chat-verify


 https://accounts.livechatinc.com/
 ?response_type=code
 &client_id=37f247f1a7431256bda730b0264f049c
 &redirect_uri=https://kycdev.bittenet.com/live-chat-verify

*/
var appConfig = fs.readFileSync(CONFIG_FILE);
var appData = JSON.parse(appConfig);
var portalConfig = fs.readFileSync(CONFIG_PORTAL);
var portalGreeting = JSON.parse(portalConfig);

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
        console.log('A new client '+socket.id +' has just been connected');
        socket.on('disconnect', () => console.log('Client disconnected'));
        //Send message
        socket.on('sendMessage', function (type, channelId, recipientId, messageText) {
            if (type === 'Facebook') {
                sendTextMessage(channelId, recipientId, messageText);
            } else if (type === 'Line') {
                sendLineTextMessage(channelId, recipientId, messageText);
            } else if (type === 'LiveChat') {
                sendLiveChatTextMessage(recipientId, messageText).then(function () {
                    //do nothing.
                });
            } else if (type === 'Portal') {
                portalReceiveMessage(socket, recipientId, messageText);
            }
        });
        //Send attachment from url
        socket.on('sendAttachment', function (type, channelId, recipientId, fileType, url, previewUrl) {
            if (type === 'Line') {
                sendLineImage(channelId, recipientId, url, previewUrl);
            } else if (type === 'Facebook') {
                sendAttachment(channelId, recipientId, url, fileType);
            } else if (type === 'LiveChat') {
                sendLiveChatFileMessage(recipientId, url).then(function () {
                    //do nothing
                });
            }
        });
        //Mark as seen
        socket.on('seen', function (channelId, recipientId) {
            sendMarkSeen(channelId, recipientId);
        });
        //Update Status / Assigned to
        socket.on('updateAssignedStatus', function (recipientId, data) {
            io.emit('updateAssignedStatus', recipientId, data);
        });

        //Portal Connection
        socket.on('portalRegister', function (portalId, portalName) {
            const roomName = PORTAL_PREFIX + portalId;
            if (!io.sockets.adapter.rooms[roomName]) {
                //send greeting - create session
                portalSendGreetings(socket, portalId, portalName);
            }
            socket.join(roomName);
            socket.on('disconnect', function () {
                setTimeout(function () {
                    if (!io.sockets.adapter.rooms[roomName]) {
                        portalEndChat(socket, roomName, portalId, portalName, 'User has left the chat.');
                    }
                }, 30 * 1000);
            });

            socket.on('endChat', function () {
                portalEndChat(socket, roomName, portalId, portalName, 'User has ended the chat.');
            });


        });

        socket.on('portalSendMessage', function (portalId, portalName, message) {
            portalSendMessage(socket, portalId, portalName, message);
        });

        socket.on('portalSendNotify', function (portalId, portalName, message) {
            portalSendMessage(socket, portalId, portalName, message, 'notify');
        });

        socket.on('portalSendCTA', function (portalId, portalName, message) {
            portalSendCTA(socket, portalId, portalName, message);
        });

    });

    /**
     * API FOR WEB
     */
    app.post('/api/conversations', async function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }

        const resPerPage = parseInt(req.query.limit) || 15;
        const page = parseInt(req.query.page) || 1;
        try {
            let output = [];
            let next;
            if (req.query.recipient) {
                const recipient = await Recipient.findOne({recipient_id: req.query.recipient});
                let msg = await Message.findOne({recipient_id: recipient.recipient_id}).sort('-created');
                let message = {};
                if (msg) {
                    message = {
                        type: msg.type,
                        text: msg.type === 'text' || msg.type === 'notify' ? msg.message_text : '(' + msg.type + ')',
                        created: msg.created
                    };
                }
                output.push({
                    id: recipient.recipient_id,
                    name: recipient.recipient_name,
                    email: recipient.email,
                    updated_time: recipient.last_message,
                    type: recipient.type,
                    message: message,
                    channel_id: recipient.channel_id
                });
                next = '';
            } else {
                const recipients = await Recipient.find()
                    .sort('-last_message')
                    .skip((resPerPage * page) - resPerPage)
                    .limit(resPerPage);
                const count = await Recipient.estimatedDocumentCount();
                const max = Math.ceil(count / resPerPage);

                for (const recipient of recipients) {
                    let msg = await Message.findOne({recipient_id: recipient.recipient_id}).sort('-created');
                    let message = {};
                    if (msg) {
                        message = {
                            type: msg.type,
                            text: msg.type === 'text' || msg.type === 'notify' ? msg.message_text : '(' + msg.type + ')',
                            created: msg.created
                        };
                    }
                    output.push({
                        id: recipient.recipient_id,
                        name: recipient.recipient_name,
                        email: recipient.email,
                        updated_time: recipient.last_message,
                        type: recipient.type,
                        message: message,
                        channel_id: recipient.channel_id
                    });
                }
                next = (page + 1) <= max ? (page + 1) : '';
            }

            res.json({
                data: output,
                next: next,
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
            const messages = await Message.find({recipient_id: recipientId})
                .sort('-created')
                .skip((resPerPage * page) - resPerPage)
                .limit(resPerPage);
            const count = await Message.find({recipient_id: recipientId}).countDocuments();
            const max = Math.ceil(count / resPerPage);

            res.json({
                data: messages,
                next: (page + 1) <= max ? (page + 1) : '',
            });
        } catch (err) {
            throw new Error(err);
        }
    });

    app.post('/api/history', async function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }

        const recipientId = req.query.recipient;
        const start = req.query.start;
        const end = req.query.end;

        try {
            const messages = await Message.find({
                recipient_id: recipientId,
                created: {
                    $gte: new Date(start + ' UTC'),
                    $lte: end !== '' ? new Date(end + ' UTC') : new Date()
                }
            }).sort('-created');

            res.json({
                data: messages
            });
        } catch (err) {
            throw new Error(err);
        }
    });

    app.post('/api/config', async function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(req.body));
        appData = req.body;
        res.sendStatus(200);
    });

    app.post('/api/portal', async function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }
        fs.writeFileSync(CONFIG_PORTAL, JSON.stringify(req.body));
        portalGreeting = req.body;
        res.sendStatus(200);
    });
    /**
     * Line Webhook
     */

    app.post('/line/:channel/webhook', function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }
        var data = req.body;
        var channel = req.params.channel;
        data.events.forEach(function (entry) {
            if (entry.type === 'message') {
                receivedLineMessage(channel, entry);
            }
        });
        res.sendStatus(200);
    });
    /**
     * Live Chat Webhook
     */

    app.get('/live-chat-verify', function (req, res) {
        const code = req.query.code;
        request({
            url: 'https://accounts.livechatinc.com/token',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                grant_type: "authorization_code",
                code: code,
                client_id: LIVECHAT_CLIENT_ID,
                client_secret: LIVECHAT_CLIENT_SECRET,
                redirect_uri: SERVER_URL + '/live-chat-verify'
            })
        }, function (error, response, body) {
            if (!error && response.statusCode === 200) {
                fs.writeFileSync(LIVECHAT_CONFIG_FILE, body);
                refreshLiveChatToken().then((data) => {
                    chatSDK.init({
                        access_token: data.access_token
                    });
                });
                res.sendStatus(200);
            } else {
                res.sendStatus(500);
            }
        });
    });

    chatSDK.on('incoming_chat_thread', (data) => {
        if (data.payload.chat.users[0]) {
            let recipient = data.payload.chat.users[0];
            if (recipient.email) {
                Recipient.findOneAndUpdate(
                    {recipient_id: md5(recipient.email.toLowerCase())},
                    {
                        recipient_name: recipient.name,
                        type: 'LiveChat',
                        email: recipient.email,
                        live_chat_id: data.payload.chat.id,
                        live_customer_id: recipient.id,
                        last_message: new Date()
                    },
                    {upsert: true, new: true, setDefaultsOnInsert: true},
                    function (error) {
                        //do nothing
                    });
            }
        }
    });

    chatSDK.on('incoming_event', (data) => {
        let event = data.payload.event;
        let chatId = data.payload.chat_id;
        let attachmentSave, attachmentSend;
        switch (event.type) {
            case "message":
                Recipient.findOneAndUpdate(
                    {live_chat_id: chatId},
                    {
                        last_message: new Date(),
                    },
                    {upsert: true, new: true, setDefaultsOnInsert: true},
                    function (error, res) {
                        if (!error) {
                            if (res.live_customer_id === event.author_id) {
                                let msg = new Message({
                                    sender_id: res.recipient_id,
                                    recipient_id: res.recipient_id,
                                    type: 'text',
                                    message_id: event.id,
                                    message_text: event.text
                                });
                                msg.save(function (err, data) {
                                    if (!err) {
                                        let obj = {
                                            from: {
                                                name: res.recipient_name,
                                                id: res.recipient_id,
                                            },
                                            message: data.message_text,
                                            id: data.message_id,
                                            created_time: data.created
                                        };
                                        io.emit('receivedMessage', res.recipient_id, JSON.stringify(obj), false);
                                    }
                                });
                            } else {
                                let msg = new Message({
                                    sender_id: ADMIN_ID,
                                    recipient_id: res.recipient_id,
                                    type: 'text',
                                    message_text: event.text
                                });
                                msg.save(function (err, data) {
                                    if (!err) {
                                        let obj = {
                                            from: {
                                                name: ADMIN_NAME,
                                                id: ADMIN_ID,
                                            },
                                            message: data.message_text,
                                            id: data.message_id,
                                            created_time: data.created
                                        };
                                        io.emit('receivedMessage', res.recipient_id, JSON.stringify(obj), true);
                                    }
                                });
                            }
                        } else {
                            console.log('------error recipient------');
                            console.log(error);
                            console.log('------end error recipient------');
                        }
                    });
                break;
            case 'file' :
                Recipient.findOneAndUpdate(
                    {live_chat_id: chatId},
                    {
                        last_message: new Date(),
                    },
                    {upsert: true, new: true, setDefaultsOnInsert: true},
                    function (error, res) {
                        if (!error) {
                            if (res.live_customer_id === event.author_id) {
                                if (event.thumbnail_url) {
                                    attachmentSave = {
                                        type: 'image',
                                        name: event.name,
                                        url: event.url,
                                        preview_url: event.thumbnail_url
                                    };

                                    attachmentSend = {
                                        image_data: {
                                            url: event.url,
                                            preview_url: event.thumbnail_url,
                                        }
                                    }
                                } else {
                                    attachmentSave = {
                                        type: 'file',
                                        name: event.name,
                                        url: event.url
                                    };

                                    attachmentSend = {
                                        file_url: event.url,
                                        name: event.name
                                    }
                                }
                                let msg = new Message({
                                    sender_id: res.recipient_id,
                                    recipient_id: res.recipient_id,
                                    type: 'attachment',
                                    message_id: event.id,
                                    attachments: [attachmentSave]
                                });

                                msg.save(function (err, data) {
                                    if (!err) {
                                        let obj = {
                                            from: {
                                                name: res.recipient_name,
                                                id: res.recipient_id,
                                            },
                                            attachments: {
                                                data: [attachmentSend]
                                            },
                                            id: event.id,
                                            created_time: data.created
                                        };
                                        io.emit('receivedMessage', res.recipient_id, JSON.stringify(obj), false);
                                    }
                                });
                            } else {
                                if (event.thumbnail_url) {
                                    attachmentSave = {
                                        type: 'image',
                                        name: event.name,
                                        url: event.url,
                                        preview_url: event.thumbnail_url
                                    };

                                    attachmentSend = {
                                        image_data: {
                                            url: event.url,
                                            preview_url: event.thumbnail_url,
                                        }
                                    }
                                } else {
                                    attachmentSave = {
                                        type: 'file',
                                        name: event.name,
                                        url: event.url
                                    };

                                    attachmentSend = {
                                        file_url: event.url,
                                        name: event.name
                                    }
                                }

                                let msg = new Message({
                                    sender_id: ADMIN_ID,
                                    recipient_id: res.recipient_id,
                                    type: 'attachment',
                                    message_id: event.id,
                                    attachments: [attachmentSave]
                                });

                                msg.save(function (err, data) {
                                    if (!err) {
                                        let obj = {
                                            from: {
                                                name: ADMIN_NAME,
                                                id: ADMIN_ID,
                                            },
                                            attachments: {
                                                data: [attachmentSend]
                                            },
                                            id: event.id,
                                            created_time: data.created
                                        };
                                        io.emit('receivedMessage', res.recipient_id, JSON.stringify(obj), true);
                                    }
                                });
                            }
                        }
                    });
                break;
        }
    });

    // chatSDK.on('agent_disconnected', function () {
    //     refreshLiveChatToken().then((data) => {
    //         chatSDK.init({
    //             access_token: data.access_token
    //         });
    //     })
    // });

    chatSDK.on('thread_closed', (data) => {
        let chatId = data.payload.chat_id;
        Recipient.findOneAndUpdate(
            {live_chat_id: chatId},
            {
                last_message: new Date(),
            },
            {upsert: true, new: true, setDefaultsOnInsert: true},
            function (error, res) {
                if (!error) {
                    let msg = new Message({
                        sender_id: ADMIN_ID,
                        recipient_id: res.recipient_id,
                        type: 'notify',
                        message_text: 'Thread has been closed.'
                    });
                    msg.save(function (err, data) {
                        if (!err) {
                            let obj = {
                                message: 'Thread has been closed.',
                                type: 'notify'
                            };
                            io.emit('receivedMessage', res.recipient_id, JSON.stringify(obj), true);
                        }
                    });
                }
            });
    });

    // for restart app
    // refreshLiveChatToken().then((data) => {
    //     chatSDK.init({
    //         access_token: data.access_token
    //     });
    //
    // });
});

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function (req, res) {
//    if (!res.signature_matched) {
//        return res.sendStatus(403);
//    }
    if (req.query['hub.mode'] === 'subscribe' &&
        req.query['hub.verify_token'] === VALIDATION_TOKEN) {
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
            var pageId = pageEntry.id;
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
        var signatureHash = elements[1];

        let dataFacebook = appData['facebook'];
        let allowedFacebook = [];
        if (typeof dataFacebook !== 'undefined') {
            Object.keys(dataFacebook).forEach(function (value) {
                allowedFacebook.push(crypto.createHmac('sha1', dataFacebook[value]['secret']).update(buf).digest('hex'));
            })
            if (allowedFacebook.indexOf(signatureHash) !== -1) {
                res.signature_matched = true;
            }
        }
    }
    //verify Line
    else if (req.headers["x-line-signature"]) {
        let signature = req.headers["x-line-signature"];
        let dataLine = appData['line'];
        let allowedLine = [];
        if (typeof dataLine !== 'undefined') {
            Object.keys(dataLine).forEach(function (value) {
                allowedLine.push(crypto.createHmac('SHA256', value).update(buf).digest('base64'));
            })

            if (allowedLine.indexOf(signature) !== -1) {
                res.signature_matched = true;
            }
        }
    }
    //verify CRM
    else if (req.headers["x-crm-signature"]) {
        let signature = req.headers["x-crm-signature"];
        if (signature === CRM_VALIDATION_KEY) {
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
    var senderId = event.sender.id;
    var recipientId = event.recipient.id;
    var timeOfAuth = event.timestamp;

    // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
    // The developer can set this to an arbitrary value to associate the
    // authentication callback with the 'Send to Messenger' click event. This is
    // a way to do account linking when the user clicks the 'Send to Messenger'
    // plugin.
    var passThroughParam = event.optin.ref;

    console.log("Received authentication for user %d and page %d with pass " +
        "through param '%s' at %d", senderId, recipientId, passThroughParam,
        timeOfAuth);

    // When an authentication is received, we'll send a message back to the sender
    // to let them know it was successful.
    sendTextMessage(senderId, "Authentication successful");
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
    var recipientId = event.sender.id;
    var channelId = event.recipient.id;
    var message = event.message;
    retrieveMessageInfo(channelId, message.mid, recipientId, false);
}

function retrieveMessageInfo(channelId, id, recipientId, owner) {
    let accessToken = appData['facebook'][channelId]['token'];
    request({
        uri: 'https://graph.facebook.com/v5.0/' + recipientId + '?fields=name',
        qs: {access_token: accessToken},
        method: 'GET'
    }, function (err, res, body) {
        if (!err && res.statusCode === 200) {
            let result = JSON.parse(body);
            Recipient.findOneAndUpdate(
                {recipient_id: recipientId},
                {
                    recipient_name: result.name,
                    type: 'Facebook',
                    channel_id: channelId,
                    last_message: new Date(),
                },
                {upsert: true, new: true, setDefaultsOnInsert: true},
                function (error) {
                    if (!error) {
                        request({
                            uri: 'https://graph.facebook.com/v5.0/' + id + '?fields=from,message,attachments,sticker,created_time',
                            qs: {access_token: accessToken},
                            method: 'GET'
                        }, function (error, response, body) {
                            if (!error && response.statusCode === 200) {
                                let data = JSON.parse(body);
                                let msg;
                                if (data.sticker) {
                                    msg = new Message({
                                        sender_id: owner ? ADMIN_ID : recipientId,
                                        recipient_id: recipientId,
                                        type: 'sticker',
                                        message_id: data.id,
                                        message_text: data.sticker,
                                        created: data.created_time,
                                    });
                                } else if (data.attachments) {
                                    let attachments = [];
                                    data.attachments.data.forEach(function (i) {
                                        if (i.image_data) {
                                            attachments.push({
                                                type: 'image',
                                                url: i.image_data.url,
                                                preview_url: i.image_data.preview_url
                                            });
                                        } else if (i.video_data) {
                                            attachments.push({type: 'video', url: i.video_data.url, name: i.name})
                                        } else {
                                            attachments.push({type: 'file', url: i.file_url, name: i.name});
                                        }
                                    });
                                    msg = new Message({
                                        sender_id: owner ? ADMIN_ID : recipientId,
                                        recipient_id: recipientId,
                                        type: 'attachment',
                                        message_id: data.id,
                                        attachments: attachments,
                                        created: data.created_time,
                                    });
                                } else {
                                    msg = new Message({
                                        sender_id: owner ? ADMIN_ID : recipientId,
                                        recipient_id: recipientId,
                                        type: 'text',
                                        message_id: data.id,
                                        message_text: data.message,
                                        created: data.created_time,
                                    });
                                }
                                //Save Facebook Message
                                msg.save(function (err) {
                                    if (!err) {
                                        if (owner) {
                                            data.from.name = ADMIN_NAME;
                                            data.from.id = ADMIN_ID;
                                        }
                                        io.emit('receivedMessage', channelId, recipientId, JSON.stringify(data), owner);
                                        if (!owner) {
                                            sendGreeting('Facebook', channelId, recipientId);
                                        }

                                    }
                                });
                            } else {
                                console.error("Failed retrieving Message info", response.statusCode, response.statusMessage, body.error);
                            }
                        });
                    }
                });
        } else {
            console.log('Fail to retrieve user info', res.statusCode, res.statusMessage, body.error);
        }
    });
}

function sendMarkSeen(channelId, recipientId) {
    console.log("Mark last message as seen", recipientId);
    var messageData = {
        messaging_type: "MESSAGE_TAG",
        tag: "ACCOUNT_UPDATE",
        recipient: {
            id: recipientId
        },
        sender_action: "mark_seen"
    };

    callSendAPI(channelId, messageData);
}

function sendAttachment(channelId, recipientId, url, type) {
    if (typeof type === 'undefined') {
        type = 'file';
    }
    var messageData = {
        messaging_type: "MESSAGE_TAG",
        tag: "ACCOUNT_UPDATE",
        recipient: {
            id: recipientId
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
console.log('send attachment', messageData);
    callSendAPI(channelId, messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(channelId, recipientId, messageText) {
    var messageData = {
        messaging_type: "MESSAGE_TAG",
        tag: "ACCOUNT_UPDATE",
        recipient: {
            id: recipientId
        },
        message: {
            text: messageText
        }
    };

    callSendAPI(channelId, messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(channelId, messageData) {
    let accessToken = appData['facebook'][channelId]['token'];
    request({
        uri: 'https://graph.facebook.com/v5.0/me/messages',
        qs: {access_token: accessToken},
        method: 'POST',
        json: messageData

    }, function (error, response, body) {
        if (!error && response.statusCode === 200) {
            var recipientId = body.recipient_id;
            var messageId = body.message_id;
            if (messageId) {
                console.log("Successfully sent message with id %s to recipient %s", messageId, recipientId);
                retrieveMessageInfo(channelId, messageId, recipientId, true);
            } else {
                console.log("Successfully called Send API for recipient %s", recipientId);
            }
        } else {
            console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
            console.log('messsData', messageData);
        }
    });
}

/* ****************LINE EVENT******************* */
function receivedLineMessage(channel, event) {
    let accessToken = appData['line'][channel]['token'];
    request({
        url: 'https://api.line.me/v2/bot/profile/' + event.source.userId,
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + accessToken
        },
        encoding: null
    }, function (err, res, body) {
        let profile = JSON.parse(body);
        Recipient.findOneAndUpdate(
            {recipient_id: event.source.userId},
            {
                recipient_name: profile.displayName,
                channel_id: channel,
                type: 'Line',
                last_message: new Date(),
            },
            {upsert: true, new: true, setDefaultsOnInsert: true},
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
                                    let obj = {
                                        from: {
                                            name: profile.displayName,
                                            id: profile.userId,
                                        },
                                        message: event.message.text,
                                        id: event.message.id,
                                        created_time: data.created
                                    };
                                    io.emit('receivedMessage', channel, event.source.userId, JSON.stringify(obj), false);
                                }
                            });
                            break;
                        case 'image':
                            request({
                                url: 'https://api-data.line.me/v2/bot/message/' + event.message.id + '/content',
                                method: 'GET',
                                headers: {
                                    'Authorization': 'Bearer ' + accessToken
                                },
                                encoding: null
                            }, function (error, response, body) {
                                if (!error && response.statusCode === 200) {
                                    let dir = './public/uploads';
                                    if (!fs.existsSync(dir)) {
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
                                            let obj = {
                                                from: {
                                                    name: profile.displayName,
                                                    id: profile.userId,
                                                },
                                                attachments: {
                                                    data: [
                                                        {
                                                            image_data: {
                                                                url: SERVER_URL + '/uploads/' + event.message.id + '.png',
                                                                preview_url: SERVER_URL + '/uploads/' + event.message.id + '.png',
                                                            }
                                                        }
                                                    ]
                                                },
                                                id: event.message.id,
                                                created_time: data.created
                                            };
                                            io.emit('receivedMessage', channel, event.source.userId, JSON.stringify(obj), false);
                                        }
                                    });
                                }
                            });
                            break;
                        case 'video':
                            request({
                                url: 'https://api-data.line.me/v2/bot/message/' + event.message.id + '/content',
                                method: 'GET',
                                headers: {
                                    'Authorization': 'Bearer ' + accessToken
                                },
                                encoding: null
                            }, function (error, response, body) {
                                if (!error && response.statusCode === 200) {
                                    let dir = './public/uploads';
                                    if (!fs.existsSync(dir)) {
                                        fs.mkdirSync(dir);
                                    }
                                    let videoUrl = SERVER_URL + '/uploads/' + event.message.id + '.mp4';
                                    fs.writeFileSync(dir + '/' + event.message.id + '.mp4', Buffer.from(body));

                                    request({
                                        url: 'https://api-data.line.me/v2/bot/message/' + event.message.id + '/content/preview',
                                        method: 'GET',
                                        headers: {
                                            'Authorization': 'Bearer ' + accessToken
                                        },
                                        encoding: null
                                    }, function (er, res, bd) {
                                        let previewUrl =  SERVER_URL + '/uploads/' + event.message.id + '.png';
                                        fs.writeFileSync(dir + '/' + event.message.id + '.png', Buffer.from(bd));
                                        let msg = new Message({
                                            sender_id: event.source.userId,
                                            recipient_id: event.source.userId,
                                            type: 'attachment',
                                            message_id: event.message.id,
                                            attachments: [
                                                {
                                                    type: 'video',
                                                    url: videoUrl,
                                                    preview_url: previewUrl,
                                                }
                                            ]
                                        });

                                        msg.save(function (err, data) {
                                            if (!err) {
                                                let obj = {
                                                    from: {
                                                        name: profile.displayName,
                                                        id: profile.userId,
                                                    },
                                                    attachments: {
                                                        data: [
                                                            {
                                                                video_data: {
                                                                    url: videoUrl,
                                                                    preview_url: previewUrl,
                                                                }
                                                            }
                                                        ]
                                                    },
                                                    id: event.message.id,
                                                    created_time: data.created
                                                };
                                                io.emit('receivedMessage', channel, event.source.userId, JSON.stringify(obj), false);
                                            }
                                        });
                                    });
                                }
                            });
                            break;
                        default:
                            console.log('----Received a Line message: This file type "' + event.message.type + '" does not support yet.');
                    }

                    sendGreeting('Line', channel, event.source.userId);
                } else {
                    console.log('------error recipient------');
                    console.log(error);
                    console.log('------end error recipient------');
                }
            });
    });
}

function sendLineTextMessage(channel, recipientId, messageText) {
    let accessToken = appData['line'][channel]['token'];
    Recipient.findOneAndUpdate(
        {recipient_id: recipientId},
        {
            last_message: new Date(),
        },
        {upsert: true, new: true, setDefaultsOnInsert: true},
        function (error) {
            if (!error) {
                request({
                    url: 'https://api.line.me/v2/bot/message/push',
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + accessToken,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        to: recipientId,
                        messages: [{type: "text", text: messageText}]
                    })
                }, function (err, res, body) {
                    let msg = new Message({
                        sender_id: ADMIN_ID,
                        recipient_id: recipientId,
                        type: 'text',
                        message_text: messageText
                    });
                    msg.save(function (err, data) {
                        if (!err) {
                            let obj = {
                                from: {
                                    name: ADMIN_NAME,
                                    id: ADMIN_ID,
                                },
                                message: data.message_text,
                                id: data.message_id,
                                created_time: data.created
                            };
                            io.emit('receivedMessage', channel, recipientId, JSON.stringify(obj), true);
                        }
                    });
                });
            }
        });
}

function sendLineImage(channel, recipientId, url, previewUrl) {
    let accessToken = appData['line'][channel]['token'];
    let fileType = isImage(url) ? 'image' : 'video';
    console.log('Send line image/video', fileType);

    Recipient.findOneAndUpdate(
        {recipient_id: recipientId},
        {
            last_message: new Date(),
        },
        {upsert: true, new: true, setDefaultsOnInsert: true},
        function (error) {
            if (!error) {
                request({
                    url: 'https://api.line.me/v2/bot/message/push',
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + accessToken,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        to: recipientId,
                        messages: [{type: fileType, originalContentUrl: url, previewImageUrl: previewUrl}]
                    })
                }, function (err, res, body) {
                    let msg = new Message({
                        sender_id: ADMIN_ID,
                        recipient_id: recipientId,
                        type: 'attachment',
                        attachments: [
                            {
                                type: fileType,
                                url: url,
                                preview_url: previewUrl,
                            }
                        ]
                    });

                    msg.save(function (err, data) {
                        if (!err) {
                            let obj = {
                                from: {
                                    name: ADMIN_NAME,
                                    id: ADMIN_ID,
                                },
                                attachments: {
                                    data: [
                                        {
                                            image_data: {
                                                url: url,
                                                preview_url: previewUrl,
                                            }
                                        }
                                    ]
                                },
                                id: data.message_id,
                                created_time: data.created
                            };
                            io.emit('receivedMessage', channel, recipientId, JSON.stringify(obj), true);
                        }
                    });
                });
            }
        });
}

/* ***************END LINE EVENT**************** */


/* ***************LIVE CHAT********************* */

async function refreshLiveChatToken() {
    return new Promise((resolve) => {
        try {
            let config = fs.readFileSync(LIVECHAT_CONFIG_FILE);
            let configData = JSON.parse(config);

            request({
                url: 'https://accounts.livechatinc.com/token',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    grant_type: "refresh_token",
                    refresh_token: configData.refresh_token,
                    client_id: LIVECHAT_CLIENT_ID,
                    client_secret: LIVECHAT_CLIENT_SECRET
                })
            }, function (error, response, body) {
                if (!error && response.statusCode === 200) {
                    fs.writeFileSync(LIVECHAT_CONFIG_FILE, body);
                    let data = JSON.parse(body);
                    console.log('-----Refresh Token at ' + new Date() + ' ---------');
                    return resolve(data);
                }
            });
        } catch (e) {
            console.log('Live Chat is not authorized');
        }
    })
}

async function sendLiveChatTextMessage(recipientId, messageText) {
    const recipient = await Recipient.findOne({recipient_id: recipientId});
    if (recipient) {
        try {
            chatSDK.sendMessage(recipient.live_chat_id, messageText).then(function() {
                //do nothing
            });
        } catch (e) {
            console.log(e);
        }
    }
}

async function sendLiveChatFileMessage(recipientId, url) {
    const recipient = await Recipient.findOne({recipient_id: recipientId});
    let configData = JSON.parse(fs.readFileSync(LIVECHAT_CONFIG_FILE));

    let fileName = getFileName(url);
    let dir = './public/uploads';
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
    let filePath = dir + '/' + fileName;
    await request(url).pipe(fs.createWriteStream(filePath).on('finish', function () {
        request({
            method: 'POST',
            url: 'https://api.livechatinc.com/v3.1/agent/action/upload_file',
            headers: {
                'Authorization': configData.token_type + ' ' + configData.access_token,
                'Content-Type': 'multipart/form-data'
            },
            formData: {
                'file': fs.createReadStream(filePath)

            }
        }, async function (err, res) {
            if (!err && res.statusCode === 200) {
                let response = JSON.parse(res.body);
                await chatSDK.methodFactory({
                    action: 'send_event',
                    payload: {
                        chat_id: recipient.live_chat_id,
                        event: {
                            type: 'file',
                            url: response.url,
                            recipients: 'all'
                        }
                    }
                });
            }
        });
    }));
}

/* *************END LIVE CHAT******************* */

async function portalSendGreetings(socket, portalId, portalName) {
    /*
            var msgObj1 = {
                type: 'text',
                sender: ADMIN_NAME,
                message: 'Hi ' + portalName,
                created_time: new Date()
            },
            msgObj2 = {
                type: 'text',
                sender: ADMIN_NAME,
                message: 'What can I help you with today? Click on a topic or ask me a question!',
                created_time: new Date()
            },
            msgObj3 = {
                type: 'link',
                sender: ADMIN_NAME,
                url: 'https://google.com',
                text: 'What is the advanced network?',
                created_time: new Date()
            },
            msgObj4 = {
                type: 'link',
                sender: ADMIN_NAME,
                url: 'https://facebook.com',
                text: 'How do I go live with a domain',
                created_time: new Date()
            },
            msgObj5 = {
                type: 'cta',
                sender: ADMIN_NAME,
                text: 'How to Quick Start?',
                created_time: new Date()
            };

        setTimeout(function () {
            socket.emit('portalReceivedMessage', msgObj1, true);
        }, 1000);

        setTimeout(function () {
            socket.emit('portalReceivedMessage', msgObj2, true);
        }, 2000);

        setTimeout(function () {
            socket.emit('portalReceivedMessage', msgObj3, true);
        }, 3000);

     */
    let recipientId = PORTAL_PREFIX + portalId;
    let session = await PortalSession.findOne({recipient_id: recipientId});
    if (session === null || session.status !== 'open') {
        // Create session
        await PortalSession.findOneAndUpdate(
            {recipient_id: recipientId},
            {
                status: 'open',
                start_date: new Date(),
                end_date: '',
            },
            {upsert: true, new: true, setDefaultsOnInsert: true},
            function (error) {
                if (!error) {
                    console.log('create session for ', recipientId);
                } else {
                    console.log(error);
                }
            }
        );

        // Greeting Message
        setTimeout(function () {
            if (typeof portalGreeting.greeting !== 'undefined') {
                portalGreeting.greeting.forEach(function (val) {
                    var msgObj = {
                        type: 'text',
                        sender: ADMIN_NAME,
                        message: val.replace('{name}', portalName),
                        created_time: new Date()
                    };
                    socket.emit('portalReceivedMessage', msgObj, true);
                });
            }
        }, 1000);

        setTimeout(function () {
            if (typeof portalGreeting.quicklinks !== 'undefined') {
                for (var i in portalGreeting.quicklinks) {
                    var msgObj = {
                        type: 'cta',
                        sender: ADMIN_NAME,
                        text: i,
                        created_time: new Date()
                    };
                    socket.emit('portalReceivedMessage', msgObj, true);
                }
            }
        }, 2000);
    }
}

//Portal send to CRM
function portalSendMessage(socket, portalId, portalName, message, messageType) {
    var recipientId = PORTAL_PREFIX + portalId;
    var senderId, senderName;
        senderId = recipientId;
        senderName = portalName;

    if (typeof messageType === 'undefined' || messageType === '') {
        messageType = 'text';
    }

    Recipient.findOneAndUpdate(
        {recipient_id: recipientId},
        {
            recipient_name: portalName,
            type: 'Portal',
            channel_id: 'portal',
            last_message: new Date(),
        },
        {upsert: true, new: true, setDefaultsOnInsert: true},
        function (error) {
            if (!error) {
                let msg = new Message({
                    sender_id: senderId,
                    recipient_id: recipientId,
                    type: messageType,
                    message_text: message
                });
                msg.save(function (err, data) {
                    if (!err) {
                        let obj = {
                            type: messageType,
                            sender: senderName,
                            created_time: data.created,
                            message: message,
                            from: {
                                name: senderName,
                                id: senderId
                            },
                        };
                        //send to portal
                        io.in(recipientId).emit('portalReceivedMessage', obj, false);

                        //send to crm
                        if (typeof socket.handshake.query.enable_chat !== 'undefined' && socket.handshake.query.enable_chat === '1') {
                            io.emit('receivedMessage', 'portal', senderId, JSON.stringify(obj), false);
                        }
                    }
                });
            }
        });
}

//CRM send to Portal
function portalReceiveMessage(socket, recipientId, message) {
    var senderId = ADMIN_ID,
        senderName = ADMIN_NAME;

    Recipient.findOneAndUpdate(
        {recipient_id: recipientId},
        {
            last_message: new Date(),
        },
        {upsert: true, new: true, setDefaultsOnInsert: true},
        function (error, res) {
            if (!error) {
                let msg = new Message({
                    sender_id: senderId,
                    recipient_id: recipientId,
                    type: 'text',
                    message_text: message
                });
                msg.save(function (err, data) {
                    if (!err) {
                        let obj = {
                            type: 'text',
                            sender: senderName,
                            created_time: data.created,
                            message: message,
                            from: {
                                name: ADMIN_NAME,
                                id: ADMIN_ID
                            },
                        };
                        //send to portal
                        io.in(recipientId).emit('portalReceivedMessage', obj, true);

                        //send to crm
                        io.emit('receivedMessage', 'portal', recipientId, JSON.stringify(obj), true);
                    }
                });
            }
        });
}

//Portal click on CTA
function portalSendCTA(socket, portalId, portalName, message) {
    var recipientId = PORTAL_PREFIX + portalId;
    portalSendMessage(socket, portalId, portalName, message);
    setTimeout(function() {
        if (typeof portalGreeting.quicklinks[message] !== 'undefined') {
            portalReceiveMessage(socket, recipientId, portalGreeting.quicklinks[message]);
        }
    }, 1000);
}

//Portal end chat
async function portalEndChat(socket, roomName, portalId, portalName, message) {
    let recipientId = PORTAL_PREFIX + portalId;
    let session = await PortalSession.findOne({recipient_id: recipientId});
    if (session && session.status === 'open') {
        portalSendMessage(socket, portalId, portalName, message, 'notify');
        setTimeout(async function() {
            socket.leave(roomName);
            socket.disconnect(true);
            //close session
            let endDate = new Date();
            await PortalSession.findOneAndUpdate(
                {recipient_id: recipientId},
                {
                    status: 'close',
                    end_date: endDate,
                },
                {upsert: true, new: true, setDefaultsOnInsert: true},
                function (error) {
                    if (!error) {
                        console.log('close session ', recipientId);
                    }
                }
            );

            // Create Note
            const messages = await Message.find({
                recipient_id: recipientId,
                created: {
                    $gte: session.start_date,
                    $lte: endDate
                }
            }).sort('created');

            request({
                uri: portalGreeting.url + 'api/v1/create-note',
                method: 'POST',
                headers: {
                    'x-webhook-signature': CRM_VALIDATION_KEY
                },
                json: {
                    'contact_id' : portalId,
                    'contact_name': portalName,
                    'subject': 'Portal has received messages from ' + portalName,
                    'message': messages,
                    'parent_type': '',
                    'parent_id': '',
                }
            }, function (error, response, body) {
                if (!error && response.statusCode === 200) {
                    console.log('Create Note success', body);
                } else {
                    console.error("Failed in creating note");//, response.statusCode, response.statusMessage, body.error);
                }
            });

        }, 1000);
    }
}


async function sendGreeting(from, channelId, recipientId) {

    if (typeof appData['greeting'] === 'undefined' || appData['greeting'] === '') {
        return;
    }

    let log = await GreetingLog.findOne({recipient_id: recipientId, channel_id: channelId, date: getDateFormat(new Date())});
    if (log === null) {
        await GreetingLog.findOneAndUpdate(
            {recipient_id: recipientId, channel_id: channelId},
            {
                date: getDateFormat(new Date())
            },
            {upsert: true, new: true, setDefaultsOnInsert: true},
            function (error) {
                if (!error) {
                    switch (from) {
                        case 'Facebook':
                            sendTextMessage(channelId, recipientId, appData['greeting']);
                            break;
                        case 'Line':
                            sendLineTextMessage(channelId, recipientId, appData['greeting']);
                            break;
                    }
                }
            }
        );
    }

    setTimeout(async function () {
        if (outOfBusinessHours()) {

            let logB = await BusinessHourLog.findOne({recipient_id: recipientId, channel_id: channelId, date: getDateFormat(new Date())});
            if (logB === null) {
                await BusinessHourLog.findOneAndUpdate(
                    {recipient_id: recipientId, channel_id: channelId},
                    {
                        date: getDateFormat(new Date())
                    },
                    {upsert: true, new: true, setDefaultsOnInsert: true},
                    function (error) {
                        if (!error) {
                            switch (from) {
                                case 'Facebook':
                                    sendTextMessage(channelId, recipientId, appData['outside_business']);
                                    break;
                                case 'Line':
                                    sendLineTextMessage(channelId, recipientId, appData['outside_business']);
                                    break;
                            }
                        }
                    }
                );
            }
        }
    }, 500);
}

function outOfBusinessHours() {
    let out = true;

    if (typeof appData.outside_day !== 'undefined') {
        const weekday = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
        let today = new Date(new Date().toLocaleString('sv-SE', {timeZone: appData.outside_timezone})),
            strDay = weekday[today.getDay()],
            hh = today.getHours(),
            ii = today.getMinutes(),
            ss = today.getSeconds();


        if (hh < 10) hh = '0' + hh;
        if (ii < 10) ii = '0' + ii;
        if (ss < 10) ss = '0' + ss;
        let strTime =  hh + ":" + ii + ":" + ss;

        if (appData.outside_day.includes(strDay)) {
            if (strTime >= appData.outside_starttime && strTime <= appData.outside_endtime) {
                out = false;
            }
        }
    }

    return out;
}

function getFileName(path) {
    return path.replace(/^.*[\\\/]/, '');
}

function getDateFormat(date) {
    let mm = date.getMonth() + 1;
    let dd = date.getDate();
    if (dd < 10) dd = '0' + dd;
    if (mm < 10) mm = '0' + mm;

    return date.getFullYear() + '-' + mm + '-' + dd;
}

function isImage(url) {
    return /\.(jpg|jpeg|png|webp|avif|gif|svg)$/.test(url);
}

module.exports = app;