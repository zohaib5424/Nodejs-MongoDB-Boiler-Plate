const sendMessage = async (to, message) => {
    try {
        client.messages
            .create({
                body: message,
                to: `+${to}`,
                from: "+1(608) 680-3421",
            })
            .then(async (message) => {
                console.log(message);
                return true
            })
            .catch((error) => {
                console.log(error);
                return false
            });

    } catch (error) {
        console.error("Error sending message:", error);
    }
};
module.exports = {
    sendMessage
}