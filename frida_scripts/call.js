let target_e164 = null;

/*
 *  @description: receive configuration options. Should occur before any execution
 *  @argument: message from the Python driver with a "e164" key
 */
recv("e164", function onMessage(driverMessage) {
    if (!driverMessage.hasOwnProperty("e164")) {
        return;
    }
    target_e164 = driverMessage.e164.trim().startsWith("+") ?
        driverMessage.e164.trim() : "+" + driverMessage.e164.trim();
    send({"key": "notify", "notification": `Targeting ${target_e164}` });
    GetConvo();
});

/*
 *  @description: finds the desired contact conversation in the database and
 *  brings up the conversation
 */
function GetConvo() {
	Java.perform(function () {
		var SignalDatabase = Java.use("org.thoughtcrime.securesms.database.SignalDatabase");
		var Recipient = Java.use("org.thoughtcrime.securesms.recipients.Recipient");

		var targetId = SignalDatabase.recipients().getOrInsertFromE164(target_e164);
		var target = Recipient.resolved(targetId);
		var threadId = SignalDatabase.threads().getOrCreateThreadIdFor(target);

		Java.choose("org.thoughtcrime.securesms.conversationlist.ConversationListFragment", {
			onMatch: function(instance) {
				instance.getNavigator().goToConversation(targetId, threadId, 2, -1);
			},
			onComplete: function () { setTimeout(VideoCall, 2000) }
		});
	});
}

/*
 *  @description: brings up the video call interface by pressing the "Video
 *  Call" button
 */
function VideoCall() {
	Java.perform(function () {
		Java.choose("org.thoughtcrime.securesms.conversation.v2.ConversationFragment", {
			onMatch: function(instance) {
				instance.handleVideoCall()
			},
			onComplete: function () { setTimeout(StartCall, 2000) }
		});
	});
}

/*
 *  @description: starts the call by pressing the "Start Call" button
 */
function StartCall() {
    Java.perform(function () {
		Java.choose("org.thoughtcrime.securesms.WebRtcCallActivity", {
			onMatch: function(instance) {
				instance.startCall(true);
			},
			onComplete: function() {
            }
		});
	});
}
