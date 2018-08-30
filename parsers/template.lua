-- Step 1 - Create parser
local template = nw.createParser("template-parser", "Template Parser")

--[[
This is a template parser.  It is intended to server as a template for simple ioc idenftification and as a learning tool.

This parser uses the hunting guide meta keys Indicators of Compromise, Behaviors of Compromise, & Enablers of Compromise. 

Extracting the host header is also used as an example, but should not be implemented.


Concentrator: index-concentrator-custom.xml
	<key description="ioc" level="IndexValues" name="eoc" valueMax="1000" format="Text"/>
 	<key description="boc" level="IndexValues" name="eoc" valueMax="1000" format="Text"/>
 	<key description="eoc" level="IndexValues" name="eoc" valueMax="1000" format="Text"/>
--]]

-- Step 3 - Define meta keys to write meta into
-- declare the meta keys we'll be registering meta with
template:setKeys({
	nwlanguagekey.create("ioc", nwtypes.Text),
	nwlanguagekey.create("boc", nwtypes.Text),
	nwlanguagekey.create("eoc", nwtypes.Text),
	nwlanguagekey.create("hostheader", nwtypes.Text),
})

-- Step 4 - Do SOMETHING once your token matched

function template:IOC(token, first, last)
	nw.createMeta(self.keys["ioc"], token .. " rat")
end

function template:BOC(token, first, last)
	nw.createMeta(self.keys["boc"], "Proxy Block Virus/Spyware")
end

function template:EOC(token, first, last)
	nw.createMeta(self.keys["boc"], "Teamviewer")
end

function template:tokenReadDataExample(token, first, last)
	local payload = nw.getPayload(last+1, last+1+4096)
	if payload then
		local endmatch = payload:find('\13\10')
		if endmatch then
			local hostheader = payload:tostring(1, endmatch-1)
			if hostheader then
				nw.createMeta(self.keys["hostheader"], hostheader)
			end
		end
	end
end
-- Step 2 - Define tokens that get you close to what you want
-- declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
template:setCallbacks({
	["^gh0st"] = template.ioc,
	["<title>Virus/Spyware Download Blocked</title>"] = template.boc,
	["^Dyngate"] = template.EOC,
--	["^Host: "] = template.tokenReadDataExample,
--	["^host: "] = template.tokenReadDataExample,
})





















