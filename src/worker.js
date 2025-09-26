import { initializeParams } from './helpers/init';
import { renderErrorPage } from './pages/error';
import { fallback, getMyIP, handlePanel } from './helpers/helpers';

export default {
    async fetch(request, env) {
        try {    
            initializeParams(request, env);
            const upgradeHeader = request.headers.get('Upgrade');
            if (!upgradeHeader || upgradeHeader !== 'websocket') {            
                switch (globalThis.pathName) {                    
                    case '/update-warp':
                        return (await import('./kv/handlers')).updateWarpConfigs(request, env);

                    case `/sub/${globalThis.userID}`:
                        if (globalThis.client === 'sfa') return (await import('./cores-configs/sing-box')).getSingBoxCustomConfig(request, env, false);
                        if (globalThis.client === 'clash') return (await import('./cores-configs/clash')).getClashNormalConfig(request, env);
                        if (globalThis.client === 'xray') return (await import('./cores-configs/xray')).getXrayCustomConfigs(request, env, false);
                        return (await import('./cores-configs/normalConfigs')).getNormalConfigs(request, env);                        

                    case `/fragsub/${globalThis.userID}`:
                        return globalThis.client === 'hiddify'
                            ? (await import('./cores-configs/sing-box')).getSingBoxCustomConfig(request, env, true)
                            : (await import('./cores-configs/xray')).getXrayCustomConfigs(request, env, true);

                    case `/warpsub/${globalThis.userID}`:
                        if (globalThis.client === 'clash') return (await import('./cores-configs/clash')).getClashWarpConfig(request, env);   
                        if (globalThis.client === 'singbox' || globalThis.client === 'hiddify') return (await import('./cores-configs/sing-box')).getSingBoxWarpConfig(request, env, globalThis.client);
                        return (await import('./cores-configs/xray')).getXrayWarpConfigs(request, env, globalThis.client);

                    case '/panel':
                        return await handlePanel(request, env);
                                                      
                    case '/login':
                        return (await import('./authentication/auth')).login(request, env);
                    
                    case '/logout':                        
                        return (await import('./authentication/auth')).logout();        

                    case '/panel/password':
                        return (await import('./authentication/auth')).resetPassword(request, env);
                    
                    case '/my-ip':
                        return await getMyIP(request);

                    case '/secrets':
                        return (await import('./pages/secrets')).renderSecretsPage();

                    default:
                        return await fallback(request);
                }
            } else {
                return globalThis.pathName.startsWith('/tr') 
                    ? (await import('./protocols/trojan')).trojanOverWSHandler(request) 
                    : (await import('./protocols/vless')).vlessOverWSHandler(request);
            }
        } catch (err) {
            return await renderErrorPage(err);
        }
    }
};