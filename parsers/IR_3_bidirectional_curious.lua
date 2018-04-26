--[[
Version:	.1
IR Content Tier: 3
Date:	2015.10.21
Author:	IR TEAM - firstresponse@rsa.com

Description:
Looks for matching tokens at the start of each req/res stream

References:

Notes:
Mostly finds ghost, but will find other protocols that start each stream with a plaintext token.  May also occasionally find gibberish matches, just ignore those.  
Focus on outbound traffic (i.e. ir.general = 'first_carve') and then do some community analysis on destination IPs.

Required Index Keys:
tokenmatch
ir.general
]]--

local parserVersion = "2015.09.15"
local IR_3_bidirectional_curious_traffic = nw.createParser("IR_3_bidirectional_curious_traffic", "Looks for matching tokens at the start of each req/res stream")

local debugParser = false

local depth = 16 --Controls how far to read into each stream (16 bytes was chosen arbitrarily and can be altered should the need arise)

IR_3_bidirectional_curious_traffic:setKeys({
	nwlanguagekey.create("tokenmatch"),
	nwlanguagekey.create("ir.general")
})

function isASCII(s)
	return not s:match('[^%a%d%p%s]+')
end

function makePrintableToken(s)

--local index = s:find('[^%w%s%p]')
local index = s:find('[^%a%d !\"#%$%%&\'%(%)*%+,%-%./:;<=>%?@%[\\%]%^_`{|}~]')
if index and index ~= 1 then
	----nw.logInfo("***Index:" .. index)
	return s:sub(1,index-1)
else return nil
end
 
end

function IR_3_bidirectional_curious_traffic:SessionBegin()
--self.gh0st_request_match = nil
--self.gh0st_response_match = nil
--self.request.ran = nil
self.mytoken = nil


end

function IR_3_bidirectional_curious_traffic:StreamBegin()	
	--Request STREAM Logic
	if nw.isRequestStream() then
		--nw.logInfo("***APP TYPE:" .. nw.getAppType())
		--Read in first depth (16 by default) bytes
		local payload = nw.getPayload(1, depth)
		
		--Check each character one at a time to see if it's non-ascii
		local possible_token = payload:tostring(1,depth)
		local myToken = makePrintableToken(possible_token)
		if myToken then
			self.myToken = myToken
			--nw.logInfo("***REQUEST:self.myToken:" .. self.myToken .. "***")
			
		end
	end
	
	
	--Response Stream Logic
	
	if nw.isResponseStream() then
		--nw.logInfo("***ResponseStream***")
		--nw.logInfo("***APP TYPE:" .. nw.getAppType())
		if nw.getAppType() == 0 then --If we're still unknown by the response stream...
			--Verify we have two steams (bidirectional)
			local streams, packets, bytes, pBytes = nwsession.getStats()
			if streams == 2 then
				--Read in first depth (16 by default) bytes
				local payload = nw.getPayload(1, depth)
				
				--Check each character one at a time to see if it's non-ascii
				local possible_token = payload:tostring(1,depth)
				local myToken = makePrintableToken(possible_token)
				
				--If we got both req/res tokens.
				if myToken and self.myToken then
					--CreateMeta
					if self.myToken:find(myToken, 1, true) == 1 then
						--Token length > 1
						if (self.myToken:len() >= 4) and (myToken:len() >= 4) then
								--nw.logInfo("***self.myToken:" .. self.myToken)
								--nw.logInfo("***self.myToken:len():" .. self.myToken:len())
								--nw.logInfo("***IF MATCH RAN***")
								nw.createMeta(self.keys["ir.general"], "bidirectional curious traffic")
								nw.createMeta(self.keys["tokenmatch"], myToken)
						end
					elseif myToken:find(self.myToken, 1, true) == 1 then
						if (self.myToken:len() >= 4) and (myToken:len() >= 4) then
							--nw.logInfo("***self.myToken:" .. self.myToken)
							--nw.logInfo("***self.myToken:len():" .. self.myToken:len())
							--nw.logInfo("***ELSE MATCH RAN***")
							nw.createMeta(self.keys["ir.general"], "bidirectional curious traffic")
							nw.createMeta(self.keys["tokenmatch"], self.myToken)
						end
					end
				end
			end
		end
	end
end



IR_3_bidirectional_curious_traffic:setCallbacks({
	[nwevents.OnSessionBegin] = IR_3_bidirectional_curious_traffic.SessionBegin,
	[nwevents.OnStreamBegin] = IR_3_bidirectional_curious_traffic.StreamBegin,
})