--[[
Version:	.1
Date:	11/Nov/2014
Author:	IR TEAM - firstresponse@rsa.com
Description:


References:

Notes:

]]--
local hostname_matches_referer = nw.createParser('Hostname Matches Referer','Checks if being referred to content on the same site.')
local debugParser = false

-- Since we are using an external module, we declare it here.  
-- This must be in the parsers directory
local nwll = require('nwll')

hostname_matches_referer:setKeys({
	nwlanguagekey.create("ir.general"),
})

function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

function hostname_matches_referer:get_hostname_from_url(url)

    --nw.logInfo('url is: ' .. url)

    local first,last = string.find(url, "://", 1,10)
    
    if last then
        url = string.sub(url, last + 1, -1)
    end    
    
    -- apply the nwll.extractUrlElements function from the nwll module                    
    local host, directory, filename, extension, querystring = nwll.extractUrlElements(url)
    
    if host then
    
        --nw.logInfo('host is: ' .. host)
        return host
        
    end

end


	
function hostname_matches_referer:SessionBegin()

self.ran = nil

end

function hostname_matches_referer:tokenHTTP(token, first, last)

    --nw.logInfo('Inside tokenHTTP...')

    if self.ran then
    --do nothing as we only want to check the beginning of the session.
    else
        self.ran = 1
        local payload = nw.getPayload(first, last)
        --Pull in the packet's payload
        local packet = payload:getPacketPayload()
        local referer_end = packet:find('Referer: ')
        
        if referer_end then
        
            local header_end = packet:find('\13\10', referer_end+9, -1)
            referer = packet:tostring(referer_end + 9, header_end)
            --nw.logInfo(referer)
            referer = trim(hostname_matches_referer:get_hostname_from_url(referer))
            nw.logInfo('Referer :' .. referer)
        end
        
        
        
        local hostname_end = packet:find('Host: ')
        
        if hostname_end then
        
            local header_end = packet:find('\13\10', hostname_end+6, -1)
            hostname = packet:tostring(hostname_end + 6, header_end)
            --nw.logInfo(hostname)
            hostname = trim(hostname_matches_referer:get_hostname_from_url(hostname))
            nw.logInfo('Hostname:' .. hostname)
        
        end
        
        
        if hostname and referer and hostname ~= '' and referer ~= '' then
            nw.logInfo('Hostname is:' .. hostname .. '***')
            nw.logInfo('Referer is:' .. referer .. '***')
            
            if referer == hostname then
            
                nw.createMeta(self.keys["ir.general"], 'hostname_matches_referer')
                
            elseif referer ~= hostname then
            
                nw.createMeta(self.keys["ir.general"], 'hostname_not_matches_referer')
            
            end
        end

    end

end
 

hostname_matches_referer:setCallbacks({
	[nwevents.OnSessionBegin] = hostname_matches_referer.SessionBegin,
	[" HTTP/1.1$"] = hostname_matches_referer.tokenHTTP,
	[" http/1.1$"] = hostname_matches_referer.tokenHTTP,
	[" Http/1.1$"] = hostname_matches_referer.tokenHTTP,
	[" HTTP/1.0$"] = hostname_matches_referer.tokenHTTP,
	[" http/1.0$"] = hostname_matches_referer.tokenHTTP,
	[" Http/1.0$"] = hostname_matches_referer.tokenHTTP,
	[" HTTP/0.9$"] = hostname_matches_referer.tokenHTTP,
	[" http/0.9$"] = hostname_matches_referer.tokenHTTP,
	[" Http/0.9$"] = hostname_matches_referer.tokenHTTP,
})

