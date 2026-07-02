import fetch from "node-fetch";

export async function sendTG(data){

    const token = process.env.TG_BOT_TOKEN;

    const chat = process.env.TG_CHAT_ID;

    const text =

`🎁 Anyrouter 领币通知

👤 登录账户: ${data.user}

💰 昨日余额: ${data.before}$

💰 当前余额: ${data.after}$

⏱️ 登录时间: ${new Date().toLocaleString("zh-CN")}
`;

    await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{

        method:"POST",

        headers:{
            "Content-Type":"application/json"
        },

        body:JSON.stringify({

            chat_id:chat,

            text

        })

    });

}
