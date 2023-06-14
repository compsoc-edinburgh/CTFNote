import {
    CategoryChannel,
    ChannelType,
    Client,
    CommandInteraction,
    Interaction,
    Message,
    PermissionsBitField,
    TextBasedChannel,
    TextChannel,
} from "discord.js";
import {Commands} from "../commands";
import {createTask, getChallengesFromDatabase, getCtfIdFromDatabase,} from "../database/ctfs";
import {createPad} from "../../plugins/createTask";


export default (client: Client): void => {
    client.on("interactionCreate", async (interaction: Interaction) => {
        //check if it is a button interaction
        if (interaction.isButton()) {
            //create the ctf channels and roles
            if (interaction.customId.startsWith("create-ctf-button-")) {
                const ctfName = interaction.customId.replace("create-ctf-button-", "");
                await interaction.channel?.send(
                    `Creating the CTF channels and roles for ${ctfName}`
                );
                interaction.deferUpdate();

                const allowedRole = await interaction.guild?.roles.create({
                    name: ctfName,
                    color: "Random",
                    mentionable: true,
                })

                if (!allowedRole) return;

                const channel = await interaction.guild?.channels.create({
                    name: `${ctfName}`,
                    type: ChannelType.GuildCategory,
                    permissionOverwrites: [
                        // Set permissions for @everyone role (default permissions)
                        {
                            id: interaction.guild.roles.everyone,
                            deny: [PermissionsBitField.Flags.ViewChannel] // Deny view permission to @everyone
                        },
                        // Set permissions for the allowed role
                        {
                            id: allowedRole.id,
                            allow: [PermissionsBitField.Flags.ViewChannel] // Allow view permission to the allowed role
                        }
                    ]

                });

                interaction.guild?.channels.create({
                    name: `challenges-talk`,
                    type: ChannelType.GuildText,
                    parent: channel?.id,
                });


                // create for every challenge a channel
                const ctfId: bigint = await getCtfIdFromDatabase(ctfName);
                const challenges: any = await getChallengesFromDatabase(ctfId);

                challenges.forEach((challenge : any) => {
                    interaction.guild?.channels
                        .create({
                            name: `${challenge.title} - ${challenge.category}`,
                            type: ChannelType.GuildText,
                            parent: channel?.id,
                            topic: `${challenge.title} - ${challenge.category}`,
                        })
                        .then((channel) => {
                            if (challenge.description != "")
                                channel.send(challenge.description);
                        });
                });

                // remove message
                interaction.deleteReply();


            } else if (interaction.customId.startsWith("archive-ctf-button-")) {
                const ctfName = interaction.customId.replace("archive-ctf-button-", "");
                await interaction.channel?.send(
                    `Archiving the CTF channels and roles for ${ctfName}`
                );
                interaction.deferUpdate();

                const categoryChannel = await interaction.guild?.channels.cache.find(
                    (channel) =>
                        channel.type === ChannelType.GuildCategory && channel.name === ctfName
                ) as CategoryChannel;

                const allMessages: any[] = []

                interaction.guild?.channels.cache.map((channel) => {
                    if (channel.type === ChannelType.GuildText && channel.parentId === categoryChannel.id) {
                        fetchAllMessages(channel as TextBasedChannel).then(async (messages) => {
                            allMessages.push(messages);

                            // Wait until fetchAllMessages is completed before deleting the channels
                            await channel.delete();
                        });
                    }
                });

                await categoryChannel.delete();

                interaction.guild?.roles.cache.map((role) => {
                    if (role.name === `${ctfName}`) {
                        role.delete();
                    }
                });

                interface Message {
                    channel: string,
                    content: string,
                    author: string,
                    timestamp: string
                }

                // put the archive in the archive channel of the ctf in the description
                const niceMessages: string[] = allMessages.map((messages) => {
                    let channelName = "";
                    let niceMessage = "";

                    messages = messages.reverse();

                    if (messages.length > 0) {
                        channelName = messages[0].channel;
                        niceMessage += `## ${channelName}\n`;

                        messages.forEach((message: Message) => {

                            if (channelName != message.channel) {
                                channelName = message.channel;
                                niceMessage = `## ${channelName}\n`;
                            }

                            const timestamp = new Date(message.timestamp).toLocaleString();

                            const formattedMessage = `[${timestamp}] ${message.author}: ${message.content}`;
                            niceMessage += formattedMessage + "\n";


                        });
                    }

                    return niceMessage;
                });


                const padUrl = await createPad(`${ctfName} archive`, niceMessages.join('\n'));
                const ctfId = Number(await getCtfIdFromDatabase(ctfName));


                createTask(`${ctfName} archive`, `Archive of ${ctfName}`, "archive", "", padUrl, ctfId)
                // remove message
                interaction.deleteReply();


            }
        }

        if (interaction.isCommand() || interaction.isContextMenuCommand()) {
            await handleSlashCommand(client, interaction);
        }


    });
};


async function fetchAllMessages(channel: TextBasedChannel): Promise<any> {
    const messages = await channel.messages.fetch({limit: 100});

    const messagesCollection: any[] = [];


    messages.forEach((message: Message) => {

        if (message.author.bot) return;
        if (message.content.startsWith("/")) return;


        const channel = message.channel as TextChannel

        const channelName = channel.name
        const timestamp = message.createdTimestamp
        const author = message.author.username

        let content = ""

        if (message.attachments.size > 0) {
            message.attachments.forEach((attachment) => {
                message.content += attachment.url + " "
            });
        }

        content += message.content

        const messageObject = {
            channel: channelName,
            content: content,
            author: author,
            timestamp: timestamp
        };

        messagesCollection.push(messageObject);

    });

    return messagesCollection; // Return an array of names
}


const handleSlashCommand = async (
    client: Client,
    interaction: CommandInteraction
): Promise<void> => {
    const slashCommand = Commands.find((c) => c.name === interaction.commandName);
    if (!slashCommand) {
        await interaction.followUp({content: "An error has occurred"});
        return;
    }

    await interaction.deferReply({
        ephemeral: true,
    });

    slashCommand.run(client, interaction);
};
