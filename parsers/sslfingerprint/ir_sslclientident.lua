--[[
Version:	.1
IR Content Tier: 3 (Development)
Date:	12Dec2017
Author:	IR TEAM - firstresponse@rsa.com

References:
JA3
https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41
https://github.com/salesforce/ja3

SSL Fingerprinting - https://github.com/LeeBrotherston/tls-fingerprinting

Initial fingerprint DB - https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json

GREASE - https://tools.ietf.org/html/draft-davidben-tls-grease-00

MD5 in Lua - https://github.com/kikito/md5.lua

Notes:

TODO: 
Move lookup table to options file

]]--

local parserName = "ir_sslclientident"
local ir_3_sslfingerprint = nw.createParser(parserName, "Implements partial JA3 SSL Fingerprinting for Client Ident")

local debugParser = false


-- define options
    local options = ({
        ["ja3rawlist"] = ({
            ["name"] = "JA3 Hash to Client List",
            ["description"] = "A3 Hash List for Client Identification",
            ["type"] = "table",
            ["default"] = nil
        }),
	})
-- set options DON'T MODIFY THIS SECTION
    pcall(function()
        local optionsModule = parserName .. "_options"
        optionsModule = require(optionsModule)
        for name,parameters in pairs(options) do
            if optionsModule[name] then
                parameters.value = optionsModule[name]()
            end
        end
    end)
    for name,parameters in pairs(options) do
        -- if the value was put in quotes, get the intended value not a string
        -- e.g., "100"  -> 100
        --       "true" -> true
        if parameters.type == "number" then
            parameters.value = tonumber(parameters.value)
        elseif parameters.type == "boolean" then
            if parameters.value == "false" then
                parameters.value = false
            elseif parameters.value == "true" then
                parameters.value = true
            end
        end
        -- make sure the type of value is correct, use default value if not
        -- e.g., expected a number but got "hello world" so use default instead
        if type(parameters.value) ~= parameters.type then
            parameters.value = parameters.default
        -- make sure number values fall within minimum and maximum
        elseif parameters.type == "number" then
            -- if the definition didn't provide a minimum, use 0
            parameters.minimum = (parameters.minimum and parameters.minimum > 0 and parameters.minimum) or 0
            -- if the definition didn't provide a maximum, use 4294967295
            parameters.maximum = (parameters.maximum and parameters.maximum < 4294967295 and parameters.maximum) or 4294967295
            parameters.value =
               (parameters.value < parameters.minimum and parameters.minimum) or
               (parameters.value > parameters.maximum and parameters.maximum) or
                parameters.value
        elseif parameters.type == "string" then
            -- make sure we don't use an empty string
            if string.len(parameters.value) == 0 then
                parameters.value = parameters.default
            end
        end
    end
-- end options
local ja3rawlist = {}

if options.ja3rawlist.value then
    for i,j in pairs(options.ja3rawlist.value) do
        ja3rawlist[i] = j
    end
else
	ja3rawlist = nil
end

ir_3_sslfingerprint:setKeys({
	--nwlanguagekey.create("ssl.ja3"),
	nwlanguagekey.create("client"),
	--nwlanguagekey.create("ssl.raw"),
	nwlanguagekey.create("analysis.service"),
})

function toHexString(myPayload)
	local hexout = ''
	for i=1, myPayload:len() do
		hexout = hexout .. bit.tohex(myPayload:uint8(i),2) .. ' '
	end
	return hexout
end

function ir_3_sslfingerprint:init()
-- GREASE   https://tools.ietf.org/html/draft-davidben-tls-grease-00
self.GREASE =
{
      [2570] = true,
      [6682] = true,
      [10794] = true,
      [14906] = true,
      [19018] = true,
      [23130] = true,
      [27242] = true,
      [31354] = true,
      [35466] = true,
      [39578] = true,
      [43690] = true,
      [47802] = true,
      [51914] = true,
      [56026] = true,
      [60138] = true,
      [64250] = true
};
end

function ir_3_sslfingerprint:tlsHandshake(token, first, last)
	--Check if Client Hello
	local helloPayload = nw.getPayload(last + 3, last + 4)
	if helloPayload then
		local helloPayloadInt = helloPayload:uint8()
		if helloPayloadInt == 1 then
			if nw.isRequestStream() then
				--We are in the Handshake and Client Hello
				--nw.logInfo("Client Hello!")
				nw.createMeta(self.keys["analysis.service"], "ssl client hello")
				
				--Get small payload to get length of TLS Section
				local payload = nw.getPayload(last + 1, last + 2)
				if payload then
					--Length of the TLS section
					local payloadShort = nwpayload.uint16
					local tlsLength = payloadShort(payload, 1)
					if tlsLength then
						--nw.logInfo("tlsLength: " .. tonumber(tlsLength))
						-- get a payload object of just the TLS section (in its entirety)
						payload = nw.getPayload(last + 3, last + 3 + tlsLength - 1)
						if payload then

							local position = 1
							local handshake = payload:uint8(position)
							position = position + 1
							-- length = 3 bytes 
							position = position + 3 
							local version = payload:uint16(position)
							position  = position + 2
							
							--Verify SSL/TLS Versions are good.
							if (tonumber(version) == 768 or tonumber(version) == 769 or tonumber(version) == 770 or tonumber(version) == 771) then
								-- random = 32 bytes
								position = position + 32
								
								-- session id length
								local sessionIdLength = payload:uint8(position)
								position = position + 1 + sessionIdLength
								
								-- cipher suites
								local cipherSuitesLength = payload:uint16(position)
								position = position + 2
								--local cipherSuitesTable = {}
								local cipherSuites = ''
								if cipherSuitesLength and cipherSuitesLength > 0 and position < payload:len() then
									for i=1,cipherSuitesLength/2 do
										cipherSuite = payload:uint16(position)
										--nw.logInfo("cipherSuite: " .. cipherSuite)
										if not self.GREASE[cipherSuite] then
											cipherSuites = cipherSuites .. cipherSuite .. '-'
										end
										position = position + 2
									end

									--nw.logInfo("handshake: " .. tonumber(handshake))
									--nw.logInfo("version: " .. tonumber(version))
									--nw.logInfo("version: " .. tostring(bit.tohex(version,4)))
									--nw.logInfo("cipherSuitesLength: " .. tonumber(cipherSuitesLength))
									--nw.logInfo("cipherSuitesLength: " .. tostring(bit.tohex(cipherSuitesLength,4)))

									cipherSuites = cipherSuites:sub(1,-2)
									--nw.logInfo("cipherSuites: ".. cipherSuites)
								end
								
								--CompressionMethods  (Not used in JA3 Hash)
								local CompressionMethodsLength = payload:uint8(position)
								position = position + 1
								if CompressionMethodsLength and CompressionMethodsLength > 0 and position < payload:len() then
									--nw.logInfo("CompressionMethodsLength: " .. tonumber(CompressionMethodsLength))
									--local CompressionMethodsTable = {}
									for i=1,CompressionMethodsLength do
										--CompressionMethodsTable[i] = payload:uint8(position)
										position = position + 1
									end
								end
								
								--SSLExtensions
								local SSLExtensionTableLength = payload:uint16(position)
								position = position + 2
								--nw.logInfo("SSLExtensionTableLength: " .. tonumber(SSLExtensionTableLength))
								local SSLExtensionTypes = ''
								local ECC = ''
								local EllipticCurvePointFormat = ''
								if SSLExtensionTableLength and SSLExtensionTableLength > 0 then
									local ExtensionPosition = 1
									local ExtensionCount = 1
									local ExtType = nil
									while ExtensionPosition < SSLExtensionTableLength do
										--Read in ExtensionType
										ExtType = payload:uint16(position)
										position = position + 2
										ExtensionPosition = ExtensionPosition + 2
										--nw.logInfo("ExtType: " .. ExtType)
										
										--Read in SSLExtensionLength
										local SSLExtensionLength = payload:uint16(position)
										position = position + 2
										ExtensionPosition = ExtensionPosition + 2
										--Check for GREASE Extensions
										if not self.GREASE[ExtType] then
											--nw.logInfo("GREASE PASSED " .. ExtType)
											SSLExtensionTypes = SSLExtensionTypes .. ExtType .. '-'

											--nw.logInfo("ExtensionCount: " .. tonumber(ExtensionCount))
											--nw.logInfo("ExtensionType: " .. tonumber(SSLExtensionTypeTable[ExtensionCount]))
											--nw.logInfo("SSLExtensionLength: " .. tonumber(SSLExtensionLength))
											--nw.logInfo("ExtensionPosition: " .. tonumber(ExtensionPosition))
											
											--Handle EllipticCurve
											--if SSLExtensionTypeTable[ExtensionCount] == 10 then
											if ExtType == 10 then
												local EllipticCurveLength = payload:uint16(position)
												position = position + 2
												ExtensionPosition = ExtensionPosition + 2
												--nw.logInfo("EllipticCurveLength: " .. tonumber(EllipticCurveLength))
												
												for i=1, EllipticCurveLength/2 do
													if not self.GREASE[payload:uint16(position)] then
														ECC = ECC .. payload:uint16(position) .. '-'
													end
													position = position + 2
													ExtensionPosition = ExtensionPosition + 2
												end
												ECC = ECC:sub(1,-2) --Trim trailing -

											elseif ExtType == 11 then
											
												local EllipticCurvePointFormatLength = payload:uint8(position)
												--nw.logInfo("EllipticCurvePointFormatLength: " .. tonumber(EllipticCurvePointFormatLength))
												
												position = position + 1
												ExtensionPosition = ExtensionPosition + 1
												
												for i=1, EllipticCurvePointFormatLength do
													EllipticCurvePointFormat = EllipticCurvePointFormat .. payload:uint8(position) .. '-'
													position = position + 1
													ExtensionPosition = ExtensionPosition + 1
												end
												EllipticCurvePointFormat = EllipticCurvePointFormat:sub(1,-2) --Trim trailing -
											else
												--Skip over it
												position = position + SSLExtensionLength
												ExtensionPosition = ExtensionPosition + SSLExtensionLength
											end
										end
										ExtensionCount = ExtensionCount + 1
									end
									
									SSLExtensionTypes = SSLExtensionTypes:sub(1,-2) --Trim trailing -
									--nw.logInfo("SSLExtensionTypes: ".. SSLExtensionTypes)
								end
								
								--Create FingerPrint
								local sslFingerprint = tostring(tonumber(version)) .. ',' .. cipherSuites .. ',' .. SSLExtensionTypes .. ',' .. ECC .. ',' .. EllipticCurvePointFormat
								--nw.logInfo("SRC/DST: " .. nwsession.getSource() .. " -> " .. nwsession.getDestination()) 
								--nw.logInfo("sslFingerprint: " .. sslFingerprint)
								
								--Lookup Client in ja3 table
								if ja3rawlist then
									if ja3rawlist[sslFingerprint] then
										--nw.logInfo("client: " .. self.ja3[sslFingerprint])
										nw.createMeta(self.keys["client"], ja3rawlist[sslFingerprint])
									--else 
										--nw.logInfo("client: " .. "unknown")
										--nw.createMeta(self.keys["client"], "unknown ssl")
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

ir_3_sslfingerprint:setCallbacks({
	--[nwevents.OnSessionBegin] = ir_3_sslfingerprint.SessionBegin,
	[nwevents.OnInit] = ir_3_sslfingerprint.init,
	["\022\003\000"] = ir_3_sslfingerprint.tlsHandshake,   -- SSL 3.0 0x160300
    ["\022\003\001"] = ir_3_sslfingerprint.tlsHandshake,   -- TLS 1.0 0x160301
    ["\022\003\002"] = ir_3_sslfingerprint.tlsHandshake,   -- TLS 1.1 0x160302
    ["\022\003\003"] = ir_3_sslfingerprint.tlsHandshake,   -- TLS 1.2 0x160303
})