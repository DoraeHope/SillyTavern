const { Buffer } = require('buffer');

async function authMiddleware(req, res, next) {
    const xIpToken = req.headers['x-ip-token'];
    const API_KEY = process.env.API_KEY; // 从环境变量获取

    // 1. 检查是否存在令牌
    if (!xIpToken) {
        return res.status(401).json({
            detail: "缺少 x-ip-token 请求头。此请求头为认证所需。"
        });
    }

    try {
        // 2. 拆分JWT
        const parts = xIpToken.split('.');
        if (parts.length < 2) {
            throw new Error("无效的JWT格式");
        }

        // 3. 处理Payload
        let payloadEncoded = parts[1];
        payloadEncoded += '='.repeat((4 - (payloadEncoded.length % 4)) % 4);
        const decodedPayload = Buffer.from(payloadEncoded, 'base64').toString();
        const payload = JSON.parse(decodedPayload);

        // 4. 检查错误字段
        if (payload.error) {
            return res.status(403).json({
                detail: `访问被拒绝：平台令牌表明错误 '${payload.error}'。`
            });
        }

        // 5. 检查用户字段
        const userFromToken = payload.user;
        if (!userFromToken || typeof userFromToken !== 'string' || userFromToken.trim() === '') {
            return res.status(403).json({
                detail: "访问被拒绝：未能提供有效的用户标识。"
            });
        }

        // 6. 最终比对
        if (userFromToken !== API_KEY) {
            return res.status(403).json({
                detail: `访问被拒绝：用户 '${userFromToken}' 无权访问。`
            });
        }

        // 7. 认证通过
        next();
    } catch (error) {
        // 统一错误处理
        if (error.message.includes("JWT")) {
            return res.status(400).json({ detail: "令牌格式错误" });
        }
        console.error("处理错误:", error);
        res.status(500).json({ detail: "服务器内部错误" });
    }
}
