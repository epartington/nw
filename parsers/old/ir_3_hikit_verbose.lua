--[[
Version:	.4
IR Content Tier: 3
Date:	5/Feb/2015
Author:		IR Team - FirstResponse@rsa.com
Description:
Parser examines the first 24 bytes of every session looking for Hikit beacon. Parser focuses on the first packet that matches hikit traffic patterns.

References:
http://www.novetta.com/files/1714/1329/6231/Hikit_Preliminary_Analysis.pdf
http://www.novetta.com/files/9914/1446/8050/Hikit_Analysis-Final.pdf

Notes:
Uses OLD NW Lua Library
Also very resource intensive

Required Index Keys:
ir.alert
]]--
local ir_hikit = nw.createParser("IR_2_APT_HIKIT_VERBOSE", "Detects instances of APT Hikit - Verbose - Extracts the hikit password")
local debugParser = false

ir_hikit:setKeys({
	nwlanguagekey.create("ir.alert"),
    nwlanguagekey.create("crypto"),
	nwlanguagekey.create("threat.desc"),
	nwlanguagekey.create("password")
})

-- Converts hexstring to characters assuming alphanumeric and punctuation characters, converts cr/nl to '' if it finds some other character it returns an empty string (assuming a password would not contain those)
function string.fromhex(str)
	str = str:gsub('00','')
    local x = {}
    for y in str:gmatch('(..)') do
		if (tonumber(y,16) >= 32 and tonumber(y,16) <= 126) then
			x[#x+1] = string.char( tonumber(y, 16) )
		elseif (tonumber(y,16) == 10 or tonumber(y,16) == 13) then
			x[#x+1] = ''
		else
			return ''
		end
    end
    return table.concat( x )
end

function ir_hikit:SessionBegin()

	if nw.isRequestStream() then
		local payload = nw.getPayload(1,24) -- Get first 24 bytes of hikit v1.2 header
		
		--Check and see if any of the key bytes are 00
		local key_string = payload:find('\00',1,4)

		if key_string then
			--do nothing if any key is a null byte 
			--local key = payload:int(1,4) --Get the key from the first four bytes
			--nw.logInfo("###key: " .. bit.tohex(key) .. '###')

		else
			--Check if PacketType dword contains a null byte
			local PacketType_string = payload:find('\00',9,12)
			if PacketType_string then
				--do nothing
			else
				
				
				--Check for specific case of key = '/***' and Packettype = '****'
				local key_s = payload:tostring(1,4)
				local PacketType_s = payload:tostring(9,12)
				if key_s == '/***' and PacketType_s == '****' then
					--do nothing
				else
					
					local key = payload:int(1,4) --Get the key from the first four bytes
					local HikitVersion = payload:int(5,8) --Get the HikitVersion (possible HikitVersion_hex)
					local PacketType = payload:int(9,12) --Get the PacketType
					--local Locale = payload:int(13,16) -- Get the Locale
					--local CodePage = payload:int(17,20) -- Get the CodePage
					local PayloadSize = payload:int(21,24) -- Get the PayloadSize
					
					--nw.logInfo("###key: " .. bit.tohex(key) .. '###')
					--nw.logInfo("###PacketType: " .. bit.tohex(PacketType) .. '###')

					
					if (key and HikitVersion and PacketType and PayloadSize) then --if we got everything we're interested in

						-- XOR the key and the headers
						HikitVersion = bit.bxor(HikitVersion,key)
						PacketType = bit.bxor(PacketType,key)
						--Locale = bit.bxor(Locale,key)
						--CodePage = bit.bxor(CodePage,key)
						PayloadSize = bit.bxor(PayloadSize,key)
						PayloadSize = bit.bswap(PayloadSize)

						--convert to readable hex string
						local HikitVersion_hex = tostring(bit.tohex(HikitVersion)) --Convert HikitVersion to readable hex string
						local PacketType_hex = tostring(bit.tohex(PacketType)) -- Convert the PacketType to a readable hex string
						local PayloadSize_hex = tostring(bit.tohex(PayloadSize))
						--nw.logInfo("###HikitVersion_hex.sub(5): " .. string.sub(HikitVersion_hex,5) .. '###')
						--nw.logInfo("###HikitVersion_hex: " .. HikitVersion_hex .. '###')
						--nw.logInfo("###PacketType_hex: " .. PacketType_hex .. '###')
						--nw.logInfo("###PayloadSize: " .. PayloadSize .. '###')
						--nw.logInfo("###bit.bswap(PayloadSize): " .. bit.bswap(PayloadSize) .. '###')
						--nw.logInfo("###PayloadSize_hex: " .. PayloadSize_hex .. '###')

						-- Logic PacketType variables
						local known_HikitVersion = nil
						local hikit_packettype_match = nil

						--Look for known hikit Hikit Versions
						if (HikitVersion_hex == '31031220') or (HikitVersion_hex == '19021220') then 
							known_HikitVersion = 1
						end
						--Look for the beacon PacketType 5 match
						if (PacketType_hex == '05000000') then 
							hikit_packettype_match = 1
						end
						
						if ((known_HikitVersion) or (hikit_packettype_match)) then --If we found either a known HikitVersion_hex or PacketType match
							--Bitswap the HikitVersion to format better for output
							local HikitVersion_hex_bswap = tostring(bit.tohex(bit.bswap(HikitVersion)))
							
							--Pull in the packet's payload
							local packet = payload:getPacketPayload()
							--nw.logInfo("###packet length: " .. packet:len() .. " packet_payload: #" .. packet:tostring() .. "###")
							
							--Extract the payload by int then short then byte, skipping over the header
							local pass = {}
							local outhex	= ''
							local j=1
							for i=25, 24 + PayloadSize, 4 do
								pass[j] = packet:int(i,i+3)
								if pass[j] then
									pass[j] = bit.bxor(pass[j],key)
									outhex = outhex .. tostring(bit.tohex(pass[j]))
								else
									pass[j] = packet:short(i,i+1)
									if pass[j] then
										pass[j] = bit.bxor(pass[j],payload:short(1,2))
										outhex = outhex .. string.sub(bit.tohex(pass[j]),-4)
									else 
										pass[j] = packet:byte(i,i)
										if pass[j] then
											pass[j] = bit.bxor(pass[j],payload:byte(1,1))
											outhex = outhex .. string.sub(bit.tohex(pass[j]),-2)
										end
									end
								end
								j = j + 1
							end
							
							--convert hex string to printable characters
							local outstring = tostring(string.fromhex(outhex))
							
							--check for known passwords
							if ((outstring == 'matrix_password') or (outstring == 'iwantyou1!')) then
								nw.createMeta(self.keys["ir.alert"], "apt_hikit")
								--nw.createMeta(self.keys["crypto"], "hikit_xor_key_0x" .. bit.tohex(key))
								nw.createMeta(self.keys["password"], "hikit_" .. outstring)
								nw.createMeta(self.keys["threat.desc"], "hikit_version_" .. HikitVersion_hex_bswap)
								nw.createMeta(self.keys["threat.desc"], "apt_hikit_known_password")
							else
								if known_HikitVersion and hikit_packettype_match then
									nw.createMeta(self.keys["ir.alert"], "apt_hikit")
									nw.createMeta(self.keys["threat.desc"], "apt_hikit_known_version_and_beacon_packet-type-5")
									nw.createMeta(self.keys["threat.desc"], "hikit_version_" .. HikitVersion_hex_bswap)
									--If the outstring has entries then write out the possible password (this may catch other strings that are not passwords)
									if outstring:len() > 0 then
										nw.createMeta(self.keys["password"], "hikit_" .. outstring)
										--nw.logInfo("PASS: apt_hikit_" .. outstring .. "#")
									end
								elseif hikit_packettype_match and outstring:len() > 0 then
									--Possible hikit packetype5 (beacon) and it was able to extract a password
									nw.createMeta(self.keys["ir.alert"], "apt_hikit_possible")
									nw.createMeta(self.keys["threat.desc"], "apt_hikit_beacon_packet-type-5_and_password_exists")
									nw.createMeta(self.keys["threat.desc"], "hikit_version_" .. HikitVersion_hex_bswap)
									--If the outstring has entries then write out the possible password (this may catch other strings that are not passwords)
									if outstring:len() > 0 then
										nw.createMeta(self.keys["password"], "hikit_" .. outstring)
										--nw.logInfo("PASS: apt_hikit_" .. outstring .. "#")
									end
								elseif known_HikitVersion then
									--Possible hikit known version match
									nw.createMeta(self.keys["ir.alert"], "apt_hikit_possible")
									nw.createMeta(self.keys["threat.desc"], "apt_hikit_known_version")
									nw.createMeta(self.keys["threat.desc"], "hikit_version_" .. HikitVersion_hex_bswap)
									--If the outstring has entries then write out the possible password (this may catch other strings that are not passwords)
									if outstring:len() > 0 then
										nw.createMeta(self.keys["password"], "hikit_" .. outstring)
										--nw.logInfo("PASS: apt_hikit_" .. outstring .. "#")
									end
								elseif hikit_packettype_match then
									--Too many false positives to just match on this the beacon packet type 5 
									--[[
									--Possible hikit packet type 5 (beacon) match
									nw.createMeta(self.keys["ir.alert"], "apt_hikit_possible")
									nw.createMeta(self.keys["threat.desc"], "apt_hikit_beacon_packet-type-5")
									nw.createMeta(self.keys["threat.desc"], "hikit_version_" .. HikitVersion_hex_bswap)
									--If the outstring has entries then write out the possible password (this may catch other strings that are not passwords)
									if outstring:len() > 0 then
										nw.createMeta(self.keys["password"], "hikit_" .. outstring)
										--nw.logInfo("PASS: apt_hikit_" .. outstring .. "#")
									end
									]]--
								else
									--Possible hikit (this condition should never happen)
									nw.createMeta(self.keys["ir.alert"], "apt_hikit_possible")
									nw.createMeta(self.keys["threat.desc"], "apt_hikit_unknown")
									nw.createMeta(self.keys["threat.desc"], "hikit_version_" .. HikitVersion_hex_bswap)
									--If the outstring has entries then write out the possible password (this may catch other strings that are not passwords)
									if outstring:len() > 0 then
										nw.createMeta(self.keys["password"], "hikit_" .. outstring)
										--nw.logInfo("PASS: apt_hikit_" .. outstring .. "#")
									end
								end
							end
						end	
					end
				end
			end
		end
	end
end

ir_hikit:setCallbacks({
	[nwevents.OnSessionBegin] = ir_hikit.SessionBegin,
})

