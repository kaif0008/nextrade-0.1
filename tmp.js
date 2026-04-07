const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/nextrade').then(async () => {
    const User = mongoose.model('User', new mongoose.Schema({name: String}));
    const Message = mongoose.model('Message', new mongoose.Schema({senderId: String, receiverId: String, createdAt: Date}));
    const userId = '69cc291fd852f5d0fe1eaeb4';
    const messages = await Message.find({ $or: [{senderId: userId},{receiverId: userId}]}).sort({createdAt:-1});
    console.log('Found messages:', messages.length);
    const userIds = new Set();
    const latestMessages = {};
    messages.forEach(msg => {
        let otherId = msg.senderId === userId ? msg.receiverId : msg.senderId;
        if(!userIds.has(otherId)){
            userIds.add(otherId);
            latestMessages[otherId] = msg;
        }
    });
    const users = await User.find({_id: {$in: Array.from(userIds)}});
    console.log('Users found:', users.length);
    const convs = users.map(u => ({user: u._id, lastMsg: latestMessages[u._id.toString()]}));
    console.log(JSON.stringify(convs, null, 2));
    process.exit(0);
});
