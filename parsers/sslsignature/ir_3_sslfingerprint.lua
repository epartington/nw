--[[
Version:	.1
IR Content Tier: 3 (Development)
Date:	11Dec2017
Author:	IR TEAM - firstresponse@rsa.com

References:
JA3
https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41
https://github.com/salesforce/ja3

Initial fingerprint DB - https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json

GREASE - https://tools.ietf.org/html/draft-davidben-tls-grease-00

MD5 in Lua - https://github.com/kikito/md5.lua

Notes:

TODO: 
Move lookup table to options file

]]--


local ir_3_sslfingerprint = nw.createParser("ir_3_sslfingerprint", "Implements JA3 SSL Fingerprinting")

local debugParser = false


ir_3_sslfingerprint:setKeys({
	nwlanguagekey.create("ssl.ja3"),
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
local md5={ff=tonumber('ffffffff',16),consts={}}

string.gsub([[ d76aa478 e8c7b756 242070db c1bdceee
    f57c0faf 4787c62a a8304613 fd469501
    698098d8 8b44f7af ffff5bb1 895cd7be
    6b901122 fd987193 a679438e 49b40821
    f61e2562 c040b340 265e5a51 e9b6c7aa
    d62f105d 02441453 d8a1e681 e7d3fbc8
    21e1cde6 c33707d6 f4d50d87 455a14ed
    a9e3e905 fcefa3f8 676f02d9 8d2a4c8a
    fffa3942 8771f681 6d9d6122 fde5380c
    a4beea44 4bdecfa9 f6bb4b60 bebfbc70
    289b7ec6 eaa127fa d4ef3085 04881d05
    d9d4d039 e6db99e5 1fa27cf8 c4ac5665
    f4292244 432aff97 ab9423a7 fc93a039
    655b59c3 8f0ccc92 ffeff47d 85845dd1
    6fa87e4f fe2ce6e0 a3014314 4e0811a1
    f7537e82 bd3af235 2ad7d2bb eb86d391
    67452301 efcdab89 98badcfe 10325476 ]],"(%w+)", function (s) table.insert(md5.consts, tonumber(s,16)) end)
    --67452301 efcdab89 98badcfe 10325476 ]],"(%w+)", function (s) tinsert(md5.consts,tonumber(s,16)) end)

function md5.transform(A,B,C,D,X)
  local f=function (x,y,z) return bit.bor(bit.band(x,y),bit.band(-x-1,z)) end
  local g=function (x,y,z) return bit.bor(bit.band(x,z),bit.band(y,-z-1)) end
  local h=function (x,y,z) return bit.bxor(x,bit.bxor(y,z)) end
  local i=function (x,y,z) return bit.bxor(y,bit.bor(x,-z-1)) end
  local z=function (f,a,b,c,d,x,s,ac)
        a=bit.band(a+f(b,c,d)+x+ac,md5.ff)
        -- be *very* careful that left shift does not cause rounding!
        return bit.bor(bit.lshift(bit.band(a,bit.rshift(md5.ff,s)),s),bit.rshift(a,32-s))+b
      end
  local a,b,c,d=A,B,C,D
  local t=md5.consts

  a=z(f,a,b,c,d,X[ 0], 7,t[ 1])
  d=z(f,d,a,b,c,X[ 1],12,t[ 2])
  c=z(f,c,d,a,b,X[ 2],17,t[ 3])
  b=z(f,b,c,d,a,X[ 3],22,t[ 4])
  a=z(f,a,b,c,d,X[ 4], 7,t[ 5])
  d=z(f,d,a,b,c,X[ 5],12,t[ 6])
  c=z(f,c,d,a,b,X[ 6],17,t[ 7])
  b=z(f,b,c,d,a,X[ 7],22,t[ 8])
  a=z(f,a,b,c,d,X[ 8], 7,t[ 9])
  d=z(f,d,a,b,c,X[ 9],12,t[10])
  c=z(f,c,d,a,b,X[10],17,t[11])
  b=z(f,b,c,d,a,X[11],22,t[12])
  a=z(f,a,b,c,d,X[12], 7,t[13])
  d=z(f,d,a,b,c,X[13],12,t[14])
  c=z(f,c,d,a,b,X[14],17,t[15])
  b=z(f,b,c,d,a,X[15],22,t[16])

  a=z(g,a,b,c,d,X[ 1], 5,t[17])
  d=z(g,d,a,b,c,X[ 6], 9,t[18])
  c=z(g,c,d,a,b,X[11],14,t[19])
  b=z(g,b,c,d,a,X[ 0],20,t[20])
  a=z(g,a,b,c,d,X[ 5], 5,t[21])
  d=z(g,d,a,b,c,X[10], 9,t[22])
  c=z(g,c,d,a,b,X[15],14,t[23])
  b=z(g,b,c,d,a,X[ 4],20,t[24])
  a=z(g,a,b,c,d,X[ 9], 5,t[25])
  d=z(g,d,a,b,c,X[14], 9,t[26])
  c=z(g,c,d,a,b,X[ 3],14,t[27])
  b=z(g,b,c,d,a,X[ 8],20,t[28])
  a=z(g,a,b,c,d,X[13], 5,t[29])
  d=z(g,d,a,b,c,X[ 2], 9,t[30])
  c=z(g,c,d,a,b,X[ 7],14,t[31])
  b=z(g,b,c,d,a,X[12],20,t[32])

  a=z(h,a,b,c,d,X[ 5], 4,t[33])
  d=z(h,d,a,b,c,X[ 8],11,t[34])
  c=z(h,c,d,a,b,X[11],16,t[35])
  b=z(h,b,c,d,a,X[14],23,t[36])
  a=z(h,a,b,c,d,X[ 1], 4,t[37])
  d=z(h,d,a,b,c,X[ 4],11,t[38])
  c=z(h,c,d,a,b,X[ 7],16,t[39])
  b=z(h,b,c,d,a,X[10],23,t[40])
  a=z(h,a,b,c,d,X[13], 4,t[41])
  d=z(h,d,a,b,c,X[ 0],11,t[42])
  c=z(h,c,d,a,b,X[ 3],16,t[43])
  b=z(h,b,c,d,a,X[ 6],23,t[44])
  a=z(h,a,b,c,d,X[ 9], 4,t[45])
  d=z(h,d,a,b,c,X[12],11,t[46])
  c=z(h,c,d,a,b,X[15],16,t[47])
  b=z(h,b,c,d,a,X[ 2],23,t[48])

  a=z(i,a,b,c,d,X[ 0], 6,t[49])
  d=z(i,d,a,b,c,X[ 7],10,t[50])
  c=z(i,c,d,a,b,X[14],15,t[51])
  b=z(i,b,c,d,a,X[ 5],21,t[52])
  a=z(i,a,b,c,d,X[12], 6,t[53])
  d=z(i,d,a,b,c,X[ 3],10,t[54])
  c=z(i,c,d,a,b,X[10],15,t[55])
  b=z(i,b,c,d,a,X[ 1],21,t[56])
  a=z(i,a,b,c,d,X[ 8], 6,t[57])
  d=z(i,d,a,b,c,X[15],10,t[58])
  c=z(i,c,d,a,b,X[ 6],15,t[59])
  b=z(i,b,c,d,a,X[13],21,t[60])
  a=z(i,a,b,c,d,X[ 4], 6,t[61])
  d=z(i,d,a,b,c,X[11],10,t[62])
  c=z(i,c,d,a,b,X[ 2],15,t[63])
  b=z(i,b,c,d,a,X[ 9],21,t[64])

  return A+a,B+b,C+c,D+d
end

-- convert little-endian 32-bit int to a 4-char string
local function leIstr(i)
  local f=function (s) return string.char(bit.band(bit.rshift(i,s),255)) end
  return f(0)..f(8)..f(16)..f(24)
end

  -- convert raw string to big-endian int
  local function beInt(s)
    local v=0
    for i=1,string.len(s) do v=v*256+string.byte(s,i) end
    return v
  end
  -- convert raw string to little-endian int
  local function leInt(s)
    local v=0
    for i=string.len(s),1,-1 do v=v*256+string.byte(s,i) end
    return v
  end
  -- cut up a string in little-endian ints of given size
  local function leStrCuts(s,...)
    local o,r=1,{}
    for i=1,#arg do
      table.insert(r,leInt(string.sub(s,o,o+arg[i]-1)))
      o=o+arg[i]
    end
    return r
  end

function md5.Calc(s)
  local msgLen=string.len(s)
  local padLen=56- msgLen % 64
  if msgLen % 64 > 56 then padLen=padLen+64 end
  if padLen==0 then padLen=64 end
  s=s..string.char(128)..string.rep(string.char(0),padLen-1)
  s=s..leIstr(8*msgLen)..leIstr(0)
  assert(string.len(s) % 64 ==0)
  local t=md5.consts
  local a,b,c,d=t[65],t[66],t[67],t[68]
  for i=1,string.len(s),64 do
    local X=leStrCuts(string.sub(s,i,i+63),4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4)
    assert(#X==16)
    X[0]=table.remove(X,1) -- zero based!
    a,b,c,d=md5.transform(a,b,c,d,X)
  end
  local swap=function (w) return beInt(leIstr(w)) end
  return string.format("%08x%08x%08x%08x",swap(a),swap(b),swap(c),swap(d))
end

--[[
function ir_3_sslfingerprint:SessionBegin()
self.mytoken = nil
--nw.logInfo("***self.myToken:" .. self.myToken)
end
--]]
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
    self.ja3hash = ({
["93948924e733e9df15a3bb44404cd909"] = "Adium 1.5.10 (a)",
["e4adf57bf4a7a2dc08e9495f1b05c0ea"] = "Adium 1.5.10 (b)",
["d5169d6e19447685bf6f1af8c055d94d"] = "AirCanada Android App",
["0bb402a703d08a608bf82763b1b63313"] = "AirCanada Android App",
["662fdc668dd6af994a0f903dbcf25d66"] = "Android App",
["515601c4141e718865697050a7a1765f"] = "Android Google API Access",
["855953256ecc8e2b6d2360aff8e5d337"] = "Android Webkit Thing",
["99d8afeec9a4422120336ad720a5d692"] = "Android Webkit Thing",
["85bb8aa8e5ba373906348831bdbed41a"] = "Android Webkit Thing",
["1aab4c2c84b6979c707ed052f724734b"] = "Android Webkit Thing",
["5331a12866e19199b363f6e903381498"] = "Android Webkit Thing",
["25b72c88f837567856118febcca761e0"] = "Android Webkit Thing",
["d4693422c5ce1565377aca25940ad80c"] = "Apple Push Notification System",
["3e404f1e1b5a79e614d7543a79f3a1da"] = "Apple Spotlight Search (OSX)",
["69b2859aec70e8934229873fe53902fd"] = "Apple Spotlight",
["6b9b64bbe95ea112d02c8812fc2e7ef0"] = "Apple Spotlight",
["e5e4c0eeb02fdcf30af8235b4de07780"] = "Apple Spotlight",
["97827640b0c15c83379b7d71a3c2c5b4"] = "Apple SpotlightNetHelper (OSX)",
["47e42b00af27b87721e526ff85fd2310"] = "Apple usbmuxd iOS socket multiplexer",
["b677934e592ece9e09805bf36cd68d8a"] = "AppleWebKit/533.1 (KHTML like Gecko) Version/4.0 Mobile Safari/533.1",
["1a6ef47ab8325fbb42c447048cea9167"] = "AppleWebKit/533.1 (KHTML like Gecko) Version/4.0 Mobile Safari/533.1",
["ef323f542a99ab12d6b5348bf039b7b4"] = "AppleWebKit/534.30 (KHTML like Gecko) Version/4.0 Safari & Safari Mobile/534.30",
["e1e03b911a28815836d79c5cdd900a20"] = "AppleWebKit/534.30",
["ef323f542a99ab12d6b5348bf039b7b4"] = "AppleWebKit/534.30",
["04e1f90d8719caabafb76d4a7b13c984"] = "AppleWebKit/534.46 Mobile/9A334",
["dc08cf4510f70bf16d4106ee22f89197"] = "AppleWebKit/534.46",
["4049550d5f57eae67d958440bdc133e4"] = "AppleWebKit/535 & Ubuntu Product Search",
["ef75a13be2ed7a82f16eefe6e84bc375"] = "AppleWebKit/600.7.12 or 600.1.4",
["eaa8a172289b09a6789a415d1faac4c9"] = "AppleWebKit/600.7.12",
["1c8a17e58c20b49e3786fc61e0533e50"] = "Atlassian SourceTree (Tested v1.6.21.0)",
["42215ee83bbf3a857a72ef42213cfbd6"] = "Atlassian SourceTree (git library?) (Tested v1.6.21.0)",
["58360f4f663a0f5657f415ac2f47fe1b"] = "Aviator (Mystery 3rd) (37.0.2062.99) (OS X)",
["5149f53b5554a31116f9d86237552ee3"] = "Aviator Updates",
["add211c763889c665ae4ab675165cbc4"] = "BlackBerry Browser (Tested BB10)",
["a921515f014005af03fc1e2c4c9e66ce"] = "BlackBerry Mail Client",
["4692263d4130929ae222ef50816527ca"] = "Blackberry Messenger (Android) 2",
["b5d42ca0e68a39d5c0a294134a21f020"] = "Blackberry",
["32b0ae286d1612c82cad93b4880ee512"] = "Blackbery Messenger (Android)",
["01aead19a1b1780978f732e056b183a6"] = "BrowserShots Script",
["a4dc1c39a68bffec1cc7767472ac85a8"] = "Browsershots",
["c3ca411515180e79c765dc2c3c8cea88"] = "BurpSuite Free (1.6.01)",
["93fbcdadc1bf98ff0e3c03e7f921edd1"] = "BurpSuite Free (1.6.01)",
["34f8cac266d07bfc6bd3966e99b54d00"] = "BurpSuite Free (tested: 1.6.32 Kali)",
["15617351d807aa3145547d0ad0c976cc"] = "BurpSuite Free (tested: 1.6.32 Kali)",
["17a40616b856ec472714cd144471e0e0"] = "Candy Crush (testing iOS 8.3)",
["64bb259b446fe13f66bcd62d1f0d33df"] = "Choqok 1.5 (KDE 4.14.18 Qt 4.8.6 on OpenSUSE 42.1)",
["d54a0979516e607a1166e6efd157301c"] = "Chrome (Possible 41.x)",
["ac67a2d0e3bd59459c32c996b5985979"] = "Chrome (Tested: 47.0.2526.XX & 48.XX (64-bit)) #1",
["34dfce2bb848da7c5dafa4d475f0ba41"] = "Chrome (Tested: 47.0.2526.XX & 48.XX (64-bit)) #2",
["937edefedb6fe13f26d1a425ef1c15a5"] = "Chrome (Tested: 47.0.2526.XX & 48.XX (64-bit)) #3",
["a342d14afad3a448029ec808295ccce9"] = "Chrome (Tested: 47.0.2526.XX & 48.XX (64-bit)) #4",
["71e74faaed87acd177bd3b47a543f476"] = "Chrome (Tested: 47.0.2526.XX & 48.XX (64-bit)) #5",
["bec8267042d5885aa3acc07b4409cafc"] = "Chrome (iOS)",
["1d64ab25ad6f7258581d43077147b9b1"] = "Chrome (tested: Version 46.0.2490.86 (64-bit) - OS X)",
["230018e44608686b64907360b6def678"] = "Chrome (tested: Version 46.0.2490.86 (64-bit) - OS X)",
["dea05e8c68dfeb28003f21d22efc0aba"] = "Chrome (tested: Version 46.0.2490.86 (64-bit) - OS X)",
["62351d5ea3cd4f21f697965b10a9bbbe"] = "Chrome 10",
["62351d5ea3cd4f21f697965b10a9bbbe"] = "Chrome 10.0.648.82 (Chromium Portable 9.0)",
["a9da823fe77cd3df081644249edbf395"] = "Chrome 11 - 18",
["a9da823fe77cd3df081644249edbf395"] = "Chrome 11.0.696.16 - 18.0.1025.33  Chrome 11.0.696.16 (Chromium Portable 9.2)",
["df4a50323dfcaf1789f72e4946a7be44"] = "Chrome 19 - 20",
["df4a50323dfcaf1789f72e4946a7be44"] = "Chrome 19.0.1084.15 - 20.0.1132.57",
["df4a50323dfcaf1789f72e4946a7be44"] = "Chrome 21.0.1180.89",
["3c8cb61208e191af38b1fbef4eacd502"] = "Chrome 22.0.1201.0",
["df4a50323dfcaf1789f72e4946a7be44"] = "Chrome 22.0.1229.96 - 23.0.1271.64 Safari/537.11",
["1ef061c02d85b7e2654e11a9959096f4"] = "Chrome 24.0.1312.57 - 28.0.1500.72 Safari/537.36",
["89d37026246d4888e78e69af4f8d1147"] = "Chrome 26.0.1410.43-27.0.1453.110 Safari/537.31",
["206ee819879457f7536d2614695a5029"] = "Chrome 29.0.1547.0",
["bbc3992faa92affc0d835717ea557e99"] = "Chrome 29.0.1547.62",
["76d36fc79db002baa1b5e741fcd863bb"] = "Chrome 29.0.1547.62",
["dc3eaee99a9221345698f8a8b2f4fc3f"] = "Chrome 30.0.0.0",
["53c7ed581cbaf36951559878fcec4559"] = "Chrome 30.0.1599.101",
["fb8a6d2441ee9eaee8b560d48a8f59df"] = "Chrome 31.0.1650.57 & 32.0.1700.76 Safari/537.36",
["f7c4dc1d9595c27369a183a5df9f7b52"] = "Chrome 31.0.1650.63",
["16d7ebc398d772ef9969d2ed2a15f4c0"] = "Chrome 33.0.1750.117",
["f3136cf565acf70dd2f98ca652f43780"] = "Chrome 33.0.1750.117",
["af0ae1083ab10ac957e394c2e7ec4634"] = "Chrome 33.0.1750.154",
["ef3364da4d76c98a669cb828f2e5283a"] = "Chrome 34.0.1847.116 & 35.0.1916.114 Safari/537.36",
["4807d61f519249470ebed0b633e707cf"] = "Chrome 34.0.1847.116 & 35.0.1916.114 Safari/537.36",
["5b348680dec77f585cfe82513213ac3a"] = "Chrome 36.0.1985.125 & 37.0.2062.102 Safari/537.36",
["52be6e88840d2211a243d9356550c4a5"] = "Chrome 36.0.1985.125 - 40.0.2214.93 Safari/537.36",
["5f775bbfc50459e900d464ca1cecd136"] = "Chrome 37.0.0.0 Safari & Mobile Safari/537.36",
["a167568462b993d5787488ece82a439a"] = "Chrome 37.0.0.0",
["98652faa7e0a4d85f91e37aa6b8c0135"] = "Chrome 37.0.2062.120",
["8b8322bad90e8bfbd66e664839b7a037"] = "Chrome 41.0.2272.89",
["aa9074aa1ff31c65d01c35b9764762b6"] = "Chrome 42.0.2311.135",
["de0963bc1f3a0f70096232b272774025"] = "Chrome 42.0.2311.135",
["3bb36ec17fef5d3da04ceeb6287314c6"] = "Chrome 43.0.2357.132 & 45.02454.94",
["cd3f72760dfd5575b91213a8016c596b"] = "Chrome 48.0.2564.116",
["5406c4a87aa6cbcb7fc469fee526a206"] = "Chrome 48.0.2564.97",
["503fe06db7ef09b2cbd771c4e784c686"] = "Chrome 49.0.2623.75",
["bd4267e1672f9df843ada7c963490a0d"] = "Chrome 50.0.2661.102 1",
["caeb3b546fc7469776d51f1f54a792ca"] = "Chrome 50.0.2661.102 2",
["aa84deda2a937ad225ef94161887b0cb"] = "Chrome 51.0.2704.106 (test)",
["473e8bad0e8e1572197be80faa1795c3"] = "Chrome 51.0.2704.84 1",
["e0b0e6c934c686fd18a5727648b3ed4f"] = "Chrome 51.0.2704.84 2",
["7ddfe8d6f8b51a90d10ab3fe2587c581"] = "Chrome 51.0.2704.84 3",
["bc76a4185cc9bd4c72471620e552618c"] = "Chrome 51.0.2704.84 4",
["8e3eea71cb5a932031d90cc0fba581bc"] = "Chrome 51.0.2704.84 5",
["653924bcb1d6fd09a048a4978574e2c5"] = "Chrome 51.0.2704.84 6",
["1ef652ecfb8e60e771a4710166afc262"] = "Chrome 51.0.2704.84 7",
["cafd1f84716def1a414c688943b99faf"] = "Chrome WebSockets (48.xxxx) - also TextSecure Desktop",
["62d8823f52dd8e1ba75a9a83e8748313"] = "Chrome WebSockets (48.xxxx)",
["3c8cb61208e191af38b1fbef4eacd502"] = "Chrome/22.0.1229.96",
["c405bbbe31c0e53ac4c8448355b2af5b"] = "Chrome/30.0.1599.101",
["2c3221f495d5e4debbb34935e1717703"] = "Chrome/41.0.2272.89",
["7f340e6caa1fa4c979df919227160ff6"] = "Cisco AnyConnect Secure Mobility Client (3.1.09013)",
["203157ed9f587f0cfd265061bf309823"] = "Citrix Receiver 4.4.0.8014",
["f865de0807a17e9cb797e618162356db"] = "Customised Postfix - Damnit Matt",
["653d342bee5001569662198a672746af"] = "DropBox (tested: 3.12.5 - Ubuntu 14.04TS & Win 10)",
["482a11a20da1629b77aaadf640478d13"] = "Dropbox (Win 8.1)",
["ede63467191e9a12300e252c41ca9004"] = "Dropbox (installer?)",
["2f8363419a9fb80ad46b380778d8eaf1"] = "Dropbox Setup (tested: 3.10.11 on Win 8.x)",
["c1e8322501b4d56d484b50bd7273e798"] = "Dropbox Splash Pages (Win 10)",
["6c141f98cd79d8b505123e555c1c3119"] = "Dropbox Windows",
["36bc8c7e10647bbfea3f740e7f05c0f1"] = "Dropbox",
["576a1288426703ae0008c42f95499690"] = "Facebook iOS",
["2872afed8370401ec6fe92acb53e5301"] = "FireFox 40.0.3 (tested Windows 8)",
["1996e434b11323df4e87f8fe0e702209"] = "FireFox 49 (TLSv1.3 enabled - I think websockets)",
["8ed0a2cdcad81fc29313910eb94941d8"] = "FireFox 49 (TLSv1.3 enabled)",
["f586111542f330901d9a3885a9c821b5"] = "FireFox 49 (dev edition)",
["3d99dda4f6992b35fdb16d7ce1b6ccba"] = "Firefox 24.0 Iceweasel24.3.0",
["c57914fadb301a73e712378023b4b177"] = "Firefox 25.0",
["755cdaa3496eb8728247a639dee17aad"] = "Firefox 26.0",
["ff9223b5c9a5d44a8a423833751fa158"] = "Firefox 27.0",
["df9bedd5713fe0cc2e9184d7c16a5913"] = "Firefox 3.0.19",
["4a9bd55341e1ffe6fedb06ad4d3010a0"] = "Firefox 3.5 - 3.6",
["4a9bd55341e1ffe6fedb06ad4d3010a0"] = "Firefox 3.5.19  3.6.27  SeaMonkey 2.0.14",
["46129449560e5731dc9c5106f111a3db"] = "Firefox 46.0",
["d06b3234356cb3df0983fc8dd02ece68"] = "Firefox 46.0",
["05ece02fb23acf2efbfff54ce4099a45"] = "Firefox 47.0 2",
["aa907c2c4720b6f54cd8b67a14cef0a3"] = "Firefox 47.x 1 / FireFox 47.x (Windows 7SP1)",
["8b18c5b0c54cba1ffb2438fe24792b63"] = "Firefox 49.0a2 Developer TLS 1.3 enabled",
["55f2bd38d462d74fb6bb72d3630aae16"] = "Firefox/10.0.11esrpre Iceape/2.7.12",
["85c420ab089dac5025034444789a8fb5"] = "Firefox/13.0-25.0",
["e98db583389531a37f2fe8d251f0f7ae"] = "Firefox/25.0",
["755cdaa3496eb8728247a639dee17aad"] = "Firefox/26.0",
["cc9bcf019b339c01d200515d1cb39092"] = "Firefox/27.0-32.0",
["45d22e6403f053bfb2cc223755588533"] = "Firefox/28.0-30.0",
["8df37d4e7430e2d9a291ae9ee500a1a9"] = "Firefox/32.0",
["c5392af25feaf95cfefe858abd01c86b"] = "Firefox/33.0",
["5ba6ed04b246c96c6839e0268a8b826f"] = "Firefox/33.0",
["ab834ac5135f2204d473878821979cea"] = "Firefox/34.0-35.00",
["9250f97ba65d86e7b0e60164c820d91a"] = "Firefox/34.0-35.00",
["2872afed8370401ec6fe92acb53e5301"] = "Firefox/37.0",
["514058a66606ae870bcc670e95ca7e68"] = "Firefox/37.0",
["2aef69b4ba1938c3a400de4188743185"] = "Firefox/6.0.1 - 12.0",
["ca0f3f4c08cbd372720beb1af7d2721f"] = "Firefox/52",
["504ecb2d3e5e83a179316f098dadbaeb"] = "Flux",
["a6090977601dc1345948f101e46d5759"] = "FullTilt Poker v16.5 (OS X) #1",
["f1b9f86645cb839bd6992e848d943898"] = "FullTilt Poker v16.5 (OS X) or DropBox",
["a3b2fe29619fdcb7a9422b8fddb37a67"] = "GMail SMTP Relay",
["94b94048a438e77122fc4eee3a6a4a26"] = "GNU Wget 1.16.1 built on darwin14.0.0",
["0267b752d6a8b5fd195096b41ea5839c"] = "GNUTLS Commandline",
["d0df7f7c9ca173059b2cd17ce5c2e5cc"] = "Git-Bash (Tested v2.6.0) / curl 7.47.1 (cygwin)",
["f8c50bbee59c526ca66da05f3dc4b735"] = "GitHub Desktop (tested build 216 on OSX)",
["c5cbafbbcf53dfbfc2a803ca3833fce2"] = "Glympse Location Tracking??",
["07ef3a7f5f8ffef08affb186284f2af4"] = "Google Calendar Agent (Tested on OSX)",
["abe568de919448adcd756aea9a136aea"] = "Google Chrome (43.0.2357.130 64-bit OSX)",
["400961c8161ba7661a7029d3f7e8bb95"] = "Google Chrome (Android)",
["072c0469aa4f2f597bb38bcc17095c51"] = "Google Chrome (tested: 43.0.2357.130 64-bit OSX)",
["c40b51e2a59425b6a2b500d569962a60"] = "Google Chrome (tested: 43.0.2357.130 64-bit OSX)",
["696cd0c8c241e19e3d6336c3d3d9e2e0"] = "Google Chrome (tested: 43.0.2357.130 64-bit OSX)",
["e8aabc4fe1fc8d47c648d37b2df7485f"] = "Google Chrome 45.0.2454.101",
["514058a66606ae870bcc670e95ca7e68"] = "Google Chrome 45.0.2454.85 or FireFox 41-42",
["7ea3e17d09294aee8425ae05588f0c66"] = "Google Chrome 46.0.2490.71 m",
["a9030ea4837810ce89fb8a3d39ca12ed"] = "Google Chrome 46.0.2490.71",
["c1741dd3d2eec548df0bcd89e08fa431"] = "Google Drive (tested: 1.26.0707.2863 - Win 8.x & Win 10)",
["b16614e71d26ba348c94bfc8e33b1767"] = "Google Earth Linux 7.1.4.1529",
["9af622c65a17a0bf90d6e9504be96a43"] = "Google Mail server starttls connection",
["50dfee94717e9640b1c384e5bd78e61e"] = "GoogleBot",
["e76ac6872939f6ebfdf75f1ea73b4daf"] = "Great Firewall of China Probe (via pcaps from https://nymity.ch/active-probing/)",
["d9b07b9095590f4ff910ceee7b6af88a"] = "HipChat",
["78273d33877a36c0c30e3fb7578ee9e7"] = "IE 11",
["4cafc7a0acf83a49317ca199b2f25c82"] = "IE 11",
["cc9bcf019b339c01d200515d1cb39092"] = "IceWeasel 31.8.0",
["a61299f9b501adcf680b9275d79d4ac6"] = "In all the malware samples - Java updater perhaps",
["a6776199188c09f5124b46b895772fa2"] = "Internet Explorer 11 .0.9600.1731.(Win 8.1)",
["a264c0bb146b2fade4410bcd61744b69"] = "Internet Explorer 11.0.9600.17959",
["d54b3eb800cbeccf99fd5d5cdcd7b5b5"] = "Internet Explorer 11.0.9600.18349 / TeamViewer 10.0.47484P / Notepad++ Update Check / Softperfect Network Scanner Update Check / Wireshark 2.0.4 Update Check",
["2db6873021f2a95daa7de0d93a1d1bf2"] = "Java 8U91 Update Check",
["ced7418dee422dd70d2a6f42bb042432"] = "K9 Mail (Android)",
["8194818a46f5533268472f2167ffec70"] = "Konqueror 4.14.18 (openSUSE Leap 42.1) 2",
["78253eb48a1431a4bbbe6bb4358464ac"] = "Konqueror 4.14.18 / Kmail 4.14.18 (openSUSE Leap 42.1) 1",
["0e0b798d0208ad365eec733b29da92a6"] = "Konqueror 4.8",
["8d2e46c9e2b1ee9b1503cab4905cb3e0"] = "MS Edge",
["f66b0314f269695fe3528ef39a27c158"] = "MS Office Components",
["2201d8e006f8f005a6b415f61e677532"] = "MSIE 10.0 Trident/6.0",
["7b3b37883b5e80065b35f27888ed2b04"] = "MSIE 10.0 Trident/6.0)",
["2baf01616e930d378df97576e2686df3"] = "MSIE 8.0 & 9.0 Trident/5.0)",
["0cbbafcdaf63cbf1e490c4a2d903f24b"] = "Mail app iOS",
["67f762b0ffe3aad00dfdb0e4b1acd8b5"] = "Malware: Dridex",
["a34e8a810b5f390fc7aa5ed711fa6993"] = "Malware: Gootkit",
["c6e36d272db78ba559429e3d845606d1"] = "Malware: Gootkit",
["b50f81ae37fb467713e167137cf14540"] = "Malware: TBot / Skynet Tor Botnet",
["b9103d9d134e0c59cafbe4ae0a8299a8"] = "Malware: Unknown traffic associated with Dridex",
["84a315236aceb31ad56f5647dc64f793"] = "Malware: https://www.virustotal.com/en/file/802d683b596d7ce7ae373b15fa4a8e8c2a237bd15bc8ef655fbd2c41239fa2c8/analysis/1433178940/",
["73fab4ba757fdd5aac4729eb20f07c04"] = "Malware: https://www.virustotal.com/file/07853289247c4c932ddfbf4c215b4e86240fab6661a6d6a85ac8ee37fe92b9be/analysis/1433596684/o",
["4954bf2b5e6592b390a89d3b1dbe550a"] = "Malware: https://www.virustotal.com/file/bbb3fbd2e8289d04733f8f005dc6410b050bee193a12ddf2f819141834e9c8fa/analysis/1433054369/",
["45c2897e06c4979bd3b8e512523590d7"] = "Malware: https://www.virustotal.com/file/bbb3fbd2e8289d04733f8f005dc6410b050bee193a12ddf2f819141834e9c8fa/analysis/1433054369/o",
["fc5574de96793b73355ca9e555748225"] = "Marble (KDE 5.21.0 QT 5.5.1 openSUSE Leap 42.1)",
["cfaa6f79904b33fdca83dbb5d4b537d4"] = "May Be Superfish",
["1b5a75e6d0f679aa312edb060ea8d932"] = "May Be Superfish",
["16f17c896273d1d098314a02e87dd4cb"] = "Metaploit http scanner (tested: 4.11.5 Kali)",
["950ccdd64d360a7b24c70678ac116a44"] = "Metasploit CCS Scanner",
["ee031b874122d97ab269e0d8740be31a"] = "Metasploit HeartBleed Scanner",
["6825b330bf9de50ccc8745553cb61b2f"] = "Metasploit SSL Scanner",
["bff2c7b5c666331bfe9afacefd1bdb51"] = "Microsoft Updater (Windows 7SP1) / TeamViewer 11.0.56083P",
["48cf5fb702315efbfc88ee3c8c94c6cb"] = "Microsoft Windows Socket (Tested: Windows 10)",
["d65ddade944f9acfe4052b2c9435eb85"] = "Mozilla Sync Services (Android)",
["c2116e5bb14394aafbefe12ade9bd8ab"] = "Mozilla Thunderbird (tested: 31.5.0)",
["6fd163150b060dd7d07add280f42f4ed"] = "Mozilla Thunderbird (tested: 38.3.0)",
["de350869b8c85de67a350c8d186f11e6"] = "Mozilla/4.0 (compatible; MSIE 6.0 or MSIE 7.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)",
["4025f224557638ee81afc4f272fd7577"] = "NVIDEA GeForce Experience",
["146c6a6537ba4cc22d874bf8ff346144"] = "NetFlix App on AppleTV (possibly others also)",
["f4262963691a8f123d4434c7308ad7fe"] = "Nikto (tested 2.1.6 - Kali)",
["5eeeafdbc41e5ca7b81c92dbefa03ab7"] = "Nikto (tested 2.1.6 - Kali)",
["a563bb123396e545f5704a9a2d16bcb0"] = "Nikto (tested v2.1.6)",
["1d095e68489d3c535297cd8dffb06cb9"] = "Non-Specific Microsoft Socket",
["43bb6a18756587426681e4964e5ea4bf"] = "OS X WebSockets",
["a35c1457421bcfaf5edaccb910bfea1d"] = "OpenConnect version v7.01",
["07aa6d7cac645c8845d6e96503f7d985"] = "OpenConnect version v7.06 / wget 1.17.1-1 (cygwin)",
["0e0b798d0208ad365eec733b29da92a6"] = "OpenSSL s_client (tested: 1.0.1f - Ubuntu 14.04TS)",
["4e6f7f036fb2b05a50ee8a686b1176a6"] = "Opera 10.53  10.60  11.61  11.64  12.02",
["ceee08c3603b53be80c8afdc98babdd6"] = "Opera 11.11  11.52",
["561271bdcbfe68504ce78b38c957eef0"] = "Opera 12.14 - 12.16",
["8b475d6105c72827a234fbd47e25b0a3"] = "Opera/9.80 (X11; Linux x86_64; U; en) Presto/2.6.30 Version/10.60",
["44f37c3ceccb551271bfe0ba6d39426c"] = "Opera/9.80 Presto/2.10.229 Version/11.62",
["a16170ff03466c8ee703dd71feda9bfe"] = "Opera/9.80 Presto/2.10.289 & Presto/2.10.229",
["b237ac4bcc16c142168df03a871677bd"] = "Opera/9.80 Presto/2.10.289 Version/12.00",
["07715901e2c6fe4c45e7c42587847d5d"] = "Opera/9.80 Presto/2.12.388",
["329ff4616732b84de926caa7fd6777b0"] = "Opera/9.80 Presto/2.12.388",
["53eb89fe6147474039c1162e4d9d3dc0"] = "Outlook 2007 (Win 8.1)",
["b74f9ecf158e0575101c16c5265a85b0"] = "Pidgin (tested 2.10.11)",
["6ea7cfa450ce959818178b420f59fec4"] = "Pocket/Slack/Duo (Android)",
["9e41b6bf545347abccf0dc8fd76083a5"] = "Polycom IP Phone Directory Lookup",
["26fa3da4032424ab61dc9be62c8e3ed0"] = "Postfix with StartTLS",
["561271bdcbfe68504ce78b38c957eef0"] = "Presto 2.12.388",
["4e6f7f036fb2b05a50ee8a686b1176a6"] = "Presto 2.5.24  2.6.30  2.10.229  2.10.289",
["ceee08c3603b53be80c8afdc98babdd6"] = "Presto 2.8.131  2.9.168",
["ef48bf8b2ccaab35642fd0a9f1bbe831"] = "PubNub data stream #1 & Apteligent",
["8cc24a6ff485c62e3eb213d2ca61cf12"] = "PubNub data stream #2",
["12ad03cb3faa2748e92c9a38faab949f"] = "Pusherapp API",
["c398c55518355639c5a866c15784f969"] = "Python Requests Library 2.4.3",
["c22dea495cef869edbeb3458adaf497f"] = "Rapid7 Nexpose",
["4b06b445e3e12cdae777cec815ab90f5"] = "Reported as -",
["90f755509cba37094eb66be02335b932"] = "RingCentral App (unknown platform) #2",
["7743db23afb26f18d632420e6c36e076"] = "RingCentral App (unknown platform)",
["24339ea346521d98a8c50fd3713090c9"] = "SSLPing Scanner 1",
["ad5d6f490f3819dc60b2a2fbe5bd1cba"] = "SSLPing Scanner 2",
["1e9557c377f8ff50b80b7f87b60b1054"] = "SSLPing Scanner 3",
["c3c59ec21835721c92571e7742fadb88"] = "SSLPing Scanner 4",
["cbcd1d81f242de31fd683d5acbc70dca"] = "Safari 525 - 533  534.57.2",
["cbcd1d81f242de31fd683d5acbc70dca"] = "Safari 525.21  525.29  531.22.7  533.21.1  534.57.2 / Adobe Reader DC 15.x Updater",
["30701f5050d504c31805594fb5c083b8"] = "Safari 534.34",
["4c551900711d12c864cfe2f95e1c98c2"] = "Safari 534.34",
["41ba55231de6643721fbe2ae25fab85d"] = "Safari 534.34",
["fb1d89e16f4dd558ad99011070785cce"] = "Safari 534.59.8",
["e2a482fbb281f7662f12ff6cc871cfe7"] = "Safari 536.30.1",
["cc5925c4720edb550491a12a35c15d4d"] = "Safari 537.71",
["88770e3ad9e9d85b2e463be2b5c5a026"] = "Safari 537.78.2",
["77310efe11f1943306ee317cf02150b7"] = "Safari/534.57.2",
["41ba55231de6643721fbe2ae25fab85d"] = "Safari/537.21",
["fa8b8ed07b1dd0e4a262bd44d31251ec"] = "ShadowServer Scanner 1",
["c05809230e9f7a6bf627a48b72dc4e1c"] = "ShadowServer Scanner 2",
["0ad94fcb7d3a2c56679fbd004f6b12cd"] = "ShadowServer Scanner 3",
["0b63812a99e66c82a20d30c3b9ba6e06"] = "Shodan",
["f59a024cf47fdb835053ebf144189a47"] = "Shodan",
["0b63812a99e66c82a20d30c3b9ba6e06"] = "Shodan",
["302579fd4ba13eca27932664f66725ad"] = "Shodan",
["109dbd9238634b21363c3d62793c029c"] = "Shodan",
["0add6ceb611a7613f97329af3b6828d9"] = "Shodan",
["3fcc12d9ee1f75a0212d1d16f7b9f8ad"] = "Shodan",
["badc09d74edf43c0204c4827a038c2fa"] = "Shodan",
["f8f522671d2d2eba5803e6c002760c05"] = "Shodan",
["9d5869f950eeca2e39196c61fdf510c8"] = "Shodan",
["11e49581344c117df2c9ceb46e5594c4"] = "Shodan",
["7dde4e4f0dceb29f711fb34b4bdbf420"] = "Signal (tested: 3.16.0 - Android)",
["07931ada5b9dd93ec706e772ee60782d"] = "Signal Chrome App",
["cfb6d1c72d09d4eaa4c7d2c0b1ecbce7"] = "SkipFish (tested: v2.10b kali)",
["7a75198d3e18354a6763860d331ff46a"] = "Skype (additional Win 10)",
["06207a1730b5deeb207b0556e102ded2"] = "Skype (multiple platforms)",
["5ef08bc989a9fcc18d5011f07d953c14"] = "Skype (tested 7.18(341) on OSX)",
["c8ada45922a3e7857e4bfd4fc13e8f64"] = "Slack Desktop App",
["3d72e4827837391cd5b6f5c6b2d5b1e1"] = "Slack",
["22cca8ed59288f4984724f0ee03484ea"] = "Slackbot Link Expander",
["f51156bcd5033603e750c8bd4db254e3"] = "SpiderOak (tested: 6.0.1)",
["cab4a6a0c7ac91c2bd9e93cb0507ad4e"] = "Synology DDNS Beacon",
["24993abb75ddda7eaf0709395e47ab4e"] = "Tenable Passive Vulnerability Scanner Plugin Updater",
["74927e242d6c3febf8cb9cab10a7f889"] = "Test FP: Dridex Malware",
["f3603b5b21cdb30f2a089b78fc2dde0d"] = "Test FP: Nuclear Exploit Kit",
["4d7a28d6f2263ed61de88ca66eb011e3"] = "Test FP: Nuclear Exploit Kit",
["38aea89b122f799954cf3f4e8878498b"] = "Test FP: Tweetdeck maybe Webkit",
["97d3b9036d5a4d7f1fe33fe730f38231"] = "TextSecure Name Lookup (Tested: Android)",
["207409c2b30e670ca50e1eac016a4831"] = "ThunderBird (v17.0 OS X)",
["4623da8b4586a8a4b86e31d689aa0c15"] = "ThunderBird (v38.0.1 OS X)",
["6fd163150b060dd7d07add280f42f4ed"] = "ThunderBird (v38.0.1 OS X)",
["4623da8b4586a8a4b86e31d689aa0c15"] = "Thunderbird 38.7.0 (openSUSE Leap 42.1)",
["0ed768d6e3bc66af60d31315afd423f2"] = "Tor Browser (tested: 5.0.1f - May clash with FF38)",
["8c9a7fe81ba61dab1454e08f42f0a004"] = "Tor Browser (v4.5.3 OS X - based on FF 31.8.0)",
["5b3eee2766b876e623ba05508d269830"] = "Tor Relay Traffic (tested 0.2.7.6)",
["79f0842a32b359d1b683c569bd07f23b"] = "Tor Relay Traffic (tested 0.2.7.6)",
["79f0842a32b359d1b683c569bd07f23b"] = "Tor Uplink (via Tails distro)",
["659007d8bae74d1053f6ca4a329d25a7"] = "Tor uplink (tested: 0.2.6.10)",
["bc329d2a71e749067424502f1f72e13a"] = "Tracking something (noted with Dropbox Installer & Skype - Win 10)",
["aea96546ac042f29fed1e2203a9b4c3f"] = "Trident/7.0",
["2a458dd9c65afbcf591cd8c2a194b804"] = "Trident/7.0",
["9a1c3fed39b016b8d81cc77dae70f60f"] = "UMich Scanner (can use: zgrab)",
["0e580f864235348848418123f96bbaa0"] = "UMich Scanner (can use: zgrab)",
["dc76bc3a4e3bc38939dfd90d8b7214b7"] = "UMich Scanner (can use: zgrab)",
["f6bae8bacf93b5e97e80b594ffeba859"] = "UNVERIFIED: May be BlueCoat proxy",
["b9b4d1f7283b5ddc59d0b8d15e386106"] = "Ubuntu Software Center",
["633e9558d4b25b46e8b1c49e10faaff4"] = "Ubuntu Software Center",
["ac206b75530d569a0a64cec378eb4b66"] = "Ubuntu Web Socket #1",
["94feb9008aeb393e76bac31b30af6ad0"] = "Ubuntu Web Socket #2",
["f1b7bbeb8b79cecd728c72bba350d173"] = "Ubuntu Web Socket #3",
["3f00755c412442e642f5572ed4f2eaf2"] = "Ubuntu Web Socket #4",
["90f6c4b0577fb24a31bea0acc1fcc27d"] = "Unidentified attack tool",
["26cdef14ec70c2d6ebd943fe8069c4da"] = "Unknown SMTP Server (used by Facebook)",
["23a9b0eb3584e358816a123c208a2c8b"] = "Unknown SMTP server (207.46.100.103)",
["18e9afaf91db6f8a2470e7435c2a1d6b"] = "Unknown TLS Scanner",
["4392ae644e5a440b3b5f84b490893589"] = "Unknown: 192.168.1.23:53352 -> 95.85.50.201:443",
["7bc3475b771c44c764614397da069d28"] = "Unknown: BrowserStack timeframe SMTP STARTLS",
["335ec05b3ddb3800a8df47641c2d8e33"] = "Unknown: Something on Android that talks to Google Analytics.. help",
["81fb3e51bf3f18c5755146c28d07431b"] = "VLC",
["cff90930827e8b0f4e5a6fcc17319954"] = "VMWare Fusion / Workstation / Player Update Check 8.x-12.x",
["48e69b57de145720885af2894f2ab9e7"] = "VMware vSphere Client (Tested v4.1.0)",
["2d96ffb535c7c7a30cad924b9b9f2b52"] = "Valve Steam Client #1",
["ab1fa6468096ab057291aa381d5de2b7"] = "Valve Steam Client #2",
["41e3681b7c8c915e33b1f80d275c19d5"] = "VirtualBox Update Poll (tested 5.0.8 r103449)",
["4c8ff2ddb1890482e5989b80e48b54d4"] = "WPScan (tested: 2.9 Kali)",
["0172e9e41a8940e6a809967e4835214a"] = "Web",
["58d97971a14d0520c5c56caa75470948"] = "WebKit per Safari 9.0.1 (11601.2.7.2)",
["9ef7a86952e78eeb83590ff4d82a5538"] = "WebKit per Safari 9.0.1 (11601.2.7.2)",
["8e1172bd5dcc4698928c7eb454a2c3de"] = "WeeChat",
["444434ebe3f52b8453c3803bff077ebd"] = "Wii-U",
["c8d1364bba308db5a4a20c65c58ffde1"] = "Win default thing a la webkit",
["aee020803d10a4d39072817184c8eedc"] = "Windows 10 Native Connection",
["205200cdaac61b110838556b834070d1"] = "Windows 10 WebSockets (inc Edge) #1",
["5a0fa8873e5ffe7d9385647adc8912d7"] = "Windows 10 WebSockets (inc Edge) #2",
["a7b2f0639f58f97aec151e015be1f684"] = "Windows 8.x Apps Store thing (unconfirmed)",
["0d15924fe8f8950a3ec3a916e97c8498"] = "Windows 8.x Builtin Mail Client",
["a8ee937cf82bb0972fecc23d63c9cd82"] = "Windows 8.x TLS Socket",
["4025f224557638ee81afc4f272fd7577"] = "Windows Diagnostic and Telemetry (also Security Essentials and Microsoft Defender) (Tested Win7)",
["2db6873021f2a95daa7de0d93a1d1bf2"] = "Windows Java Plugin (tested: v8 Update 60)",
["de364c46b0dfc283b5e38c79ceae3f8f"] = "Yahoo! Slurp Indexer",
["1202a58b454f54a47d2c216567ebd4fb"] = "Yahoo! Slurp Indexer",
["d83881675de3f6aacbcc0b2bae6f8923"] = "Yandex Bot",
["f8f5b71e02603b283e55b50d17ede861"] = "Zite (Android) 1 - May collide with Chrome",
["5ae88f37a16f1b054f2edff1c8730471"] = "Zite (Android) 2 - May collide with Chome",
["4e5e5d9fbc43697be755696191fe649a"] = "atom.io #1",
["c94858c6eb06de179493b3fac847143e"] = "atom.io #2",
["764b8952983230b0ac23dbd3741d2bb0"] = "curl (tested: 7.22.0 on Linux)",
["9f198208a855994e1b8ec82c892b7d37"] = "curl (tested: 7.43.0 OS X)",
["c458ae71119005c8bc26d38a215af68f"] = "curl 7.35.0 (tested Ubuntu 14.x  openssl 1.0.1f)",
["e14d427fab707af91e4bbd0bf03076f8"] = "curl 7.37.0 / links 2.8 / git 2.6.6 (openSUSE Leap 42.1)",
["f672d8f0e827ca1e704a9489b14dd316"] = "curl",
["e3891da2a758d67ba921e5eec0b9707d"] = "curl/7.19.7 (x86_64-redhat-linux-gnu) libcurl/7.19.7 NSS/3.16.2.3 Basic ECC zlib/1.2.3 libidn/1.18 libssh2/1.4.2",
["a698fe6c52d210e3376bb6667729d4d2"] = "fetchmail 6.3.26 (openSUSE Leap 42.1)",
["3e765b7a69050906e5e48d020921b98e"] = "git commandline (tested: 1.9. Linux)",
["f11b0fca6c063aa69d8d39e0d68b6178"] = "golang (tested: 1.4.1)",
["318b9778e96efb5090c43b514c7ab184"] = "https://www.virustotal.com/file/07853289247c4c932ddfbf4c215b4e86240fab6661a6d6a85ac8ee37fe92b9be/analysis/1433596684/",
["dc08cf4510f70bf16d4106ee22f89197"] = "iOS AppleWebKit/534.46",
["06d930b072bf052b10d0a9eea1554f60"] = "iOS AppleWebKit/536.26",
["99204897b101b15f87e9b07f67453f4e"] = "iOS Mail App (tested: iOS 9.3.3)",
["c6ecc5ba2a6ab724a7430fa4890d957d"] = "iTunes/iBooks #1",
["c07295da5465d5705a38f044e53ef7c4"] = "iTunes/iBooks #2",
["4d01f8b1afc22e138127611b62f1e6ec"] = "mitmproxy",
["8ef6a005eae3d51b652ffe41984f8869"] = "mitmproxy",
["9d5869f950eeca2e39196c61fdf510c8"] = "mutt (tested: 1.5.23 - OS X)",
["dc7c914e1817944435dd6b82a8495fbb"] = "mutt (tested: 1.5.23 OSX)",
["3fcc12d9ee1f75a0212d1d16f7b9f8ad"] = "mutt (tested: 1.6.2 OS X)",
["6761a36cfa692fcd3bc7d570b23cc168"] = "mutt",
["6fffa2be612102d25dbed5f433b8238c"] = "openssl s_client / msmtp 1.6.2 (openSUSE Leap 42.1)",
["3b6da2971936ac24457616e8ad46f362"] = "osc (python openSUSE Leap 42.1) 1",
["95baa3d2068d8c8da71990a353cf8453"] = "osc (python openSUSE Leap 42.1) 2",
["16765fe48127809dc0ca406769c9391e"] = "php script (tested 5.5.27)",
["ba502b2f5d64ac3d1d54646c0d6dd4dc"] = "py2app application (including box.net & google drive clients)",
["1a9fb04aa1b4439666672be8661f9386"] = "python-requests/2.7.0 CPython/2.6.6 Linux/2.6.32-504.23.4.el6.x86_64",
["30701f5050d504c31805594fb5c083b8"] = "rekonq1.1  Arora0.11.0",
["688b34ca00a291ece0bc07b264b1344c"] = "ruby script (tested: 2.0.0p481)",
["615788655a0e65b71e47c3ebe2302564"] = "sqlmap (tested: v1.0-dev kali)",
["1ab5d0f756e0692a975fda9a6474969f"] = "sqlmap (tested: v1.0.7.0 OS X)",
["3b8f3ace50a7c7cd5205af210f17bb70"] = "tor uplink (tested 0.2.2.35)",
["10a686de1c41107df06c21df245e24cd"] = "w3af (tested: v1.6.54 Kali 1)",
["f13e6d84b915e17f76fdf4ea8c959b4d"] = "w3af (tested: v1.6.54 Kali 2)",
["345b5717dae9006a8bcd4cb1a5f09891"] = "w3af (tested: v1.6.54 Kali 3)",
["74ebac04b642a0cab032dd46e8099fdc"] = "w3c HTML Validator",
["4056657a50a8a4e5cfac40ba48becfa2"] = "w3c HTML Validator",
["975ef0826e8485f2335db71873cb34c6"] = "w3m (tested: 0.5.3 OS X)",
["6b4b535249a1dcd95e3b4b6e9e572e5e"] = "w3m 0.5.3 (OS X version)",
["575771dbc723df24b764ac0303c19d10"] = "w3m 0.5.3 / lynx 3.2 / svn 1.8.10 (openSUSE Leap 42.1)",
["5f1d4c631ddedf942033c9ae919158b8"] = "wget (tested GNU Wget 1.16.1 & 1.17 on OS X)",
["70663c6da28b3b9ac281d7b31d6b97c3"] = "wget 1.14 (openSUSE Leap 42.1)",
["d83881675de3f6aacbcc0b2bae6f8923"] = "wget 1.18",
["11404429d240670cc018bed04e918b6f"] = "youtube-dl 2016.06.03 (openSUSE Leap 42.1)",
["cdd8179dc9c0e4802f557b62bae73d43"] = "Slack",
["888ecd3b5821a497195932b0338f2f12"] = "MS Edge",
["5bf43fbca3454853c26df6d996954aca"] = "MS Edge",
["21ed4c7ee1daeb84c72199ceaf119b24"] = "Dropbox Client",
["123b8f4705d525caffa3f2b36447f481"] = "Win10 Mail Client",
["f8e42933ba5b3990858ba621489047e3"] = "Dropbox Client",
["30b168d81e38d9a55c474c1e30eaf9f9"] = "Dropbox Client",
["388a4049af7e631f8d36eb0f909de65a"] = "One Drive",
["a1ec6fd012b9ee6f84c50339c4205270"] = "HTTRack",
["5182f54f9c6e99d117d9dde3fa2b4cff"] = "BlueCoat Proxy",
["bedb7e0ff43a24272eb0a41993c65faf"] = "Microsoft Smartscreen",
["8c5a50f1e833ed581e9cfc690814719a"] = "BurpSuite Free (Tested: 1.7.03 on Windows 10)",
["2db6873021f2a95daa7de0d93a1d1bf2"] = "BurpSuite Free (Tested: 1.7.03 on Windows 10)",
["a7f2d0376cdcfde3117bf6a8359b2ab8"] = "Chrome Version 49.0.2623.87 (64-bit) Linux",
["8a8159e6abf9fe493ca87efc38855149"] = "Chrome Version 49.0.2623.87 (64-bit) Linux",
["e330bca99c8a5256ae126a55c4c725c5"] = "Chrome Version 57.0.2987.110 (64-bit) Linux",
["d551fafc4f40f1dec2bb45980bfa9492"] = "Chrome Version 57.0.2987.110 (64-bit) Linux",
["ce694315cbb81ce95e6ae4ae8cbafde6"] = "Firefox/31 Linux",
["edf844351bc867631b5ebceda318669b"] = "Firefox/38 Linux",
["4e66f5ad78f3d9ad8d5c7c88d138db43"] = "Firefox/52 Linux",
["0ffee3ba8e615ad22535e7f771690a28"] = "Firefox/55/56 Mac/Win/Linux",
["d3b972883dfbd24fd20fc200ad8ab22a"] = "Chrome Version 61.0.3163.100(64-bit) Win10",
["94c485bca29d5392be53f2b8cf7f4304"] = "Chrome Version 60/61.0.3163/62.0.3202.94",
["bc6c386f480ee97b9d9e52d472b772d8"] = "Chrome Version 60/61.0.3163",
["fee8ec956f324c71e58a8c0baf7223ef"] = "IE 11 Win10",
["2c14bfb3f8a2067fbc88d8345e9f97f3"] = "Windows Watson WCEI Telemetry Gather",
["847b0c334fd0f6f85457054fabff3145"] = "Firefox/14.0.1 Linux",
["a50a861119aceb0ccc74902e8fddb618"] = "VMWare Update Check 6.x",
["f7baf7d9da27449e823a4003e14cd623"] = "Debian APT-CURL/1.0 (1.2.15)",
["07b4162d4db57554961824a21c4a0fde"] = "Firefox/45.0 Linux",
["c07cb55f88702033a8f52c046d23e0b2"] = "Safari/604.1.38 Macintosh",
["3e4e87dda5a3162306609b7e330441d2"] = "Safari/604.3.1 Macintosh",
["83e04bc58d402f9633983cbf22724b02"] = "Chrome/56.0.2924.87 Linux",
["9811c1bb9f0f6835d5c13a831cca4173"] = "Chrome/59.0.3071.115 Win10",
["87c6dda19108d68e526a72d9ae09fb9e"] = "Mobile Safari/537.35+ BB10",
["def8761e4bcaaf91d99801a22ac6f6d4"] = "Chrome/60.0.3112.113 Win10",
["248bdbc3873396b05198a7e001fbd49a"] = "Chrome/49.0.2623.112 WinXP",
["d8844f000e5571807e9094e0fcd795fe"] = "SCRAPER: DotBot",
["ec2e8760003621ca668b5f03e616cd57"] = "Debian APT-CURL/1.0 (1.2.20+)",
["ce5f3254611a8c095a3d821d44539877"] = "SCANNER: wordpress wp-login Firefox/40.1",
["9a35e493f961ac377f948690b5334a9c"] = "SCANNER: hoax Firefox/40.1",
["a1cb2295baf199acf82d11ba4553b4a8"] = "BOT: GoogleBot",
["706567223fbf37d112fba2d95b8ecac3"] = "BOT: Qwant",
["5c1c89f930122bccc7a97d52f73bea2c"] = "BOT: Ahrefs",
["7e72698146290dd68239f788a452e7d8"] = "iPhone OS 10_3_3 Safari 602.1",
["a9aecaa66ad9c6cfe1c361da31768506"] = "iPad; CPU OS 9_3_5  Safari 601.1",
["3ca5d63fa122552463772d3e87d276f2"] = "inoreader.com-like FeedFetcher-Google",
["05e15a226e00230c416a8cdefeb483c7"] = "SCRAPER: yandex.ru based Mozilla 4.0; MSIE 8.0; Windows NT 5.1;",
["d82cbe0b93f2b02d490a14f6bc1d421a"] = "PaleMoon Browser;  PaleMoon/27.4.2",
["35c0a31c481927f022a3b530255ac080"] = "RSiteAuditor",
["37f691b063c10372135db21579643bf1"] = "urlgrabber/3.10 yum/3.4.3",
["f22bdd57e3a52de86cda40da2d84e83b"] = "Feedly/1.0",
["11e1137464a4343105031631d470cd92"] = "mj12bot.com",
["edcf2fd479271286879efebd22bc8d16"] = "Twitterbot/1.0",
["3ca5d63fa122552463772d3e87d276f2"] = "inoreader.com ",
["6cc3c7debc31952d05ecaacb6021925f"] = "SeznamBot/3.2",
["111da7c75fee7fe934b35a8d88eb350a"] = "CRAWLER: facebookexternalhit/1.1",
["61d0d709fe7ac199ef4b2c52bc8cef75"] = "Firefox/51.0 Windows 10",
["be1a7de97ea176604a3c70622189d78d"] = "Firefox/56.0 Windows 10",
["05af1f5ca1b87cc9cc9b25185115607d"] = "Firefox/40.1 Windows 7",
["1885aa9927f99ed538ed895d9335995c"] = "Firefox/55 Windows 10",
["a88698036914a0a190ad16272037b3c9"] = "OpenVPN 11.8.0.0 Windows 7",
["7d027c5552c4d25b42d0c4124ba8604f"] = "Chrome 62.0.3202.94 (64-bit) Windows 7",
["581a3c7f54555512b8cd16e87dfe165b"] = "TOR",
	})
	end

function ir_3_sslfingerprint:tlsHandshake(token, first, last)
	--Check if Client Hello
	local helloPayload = nw.getPayload(last + 3, last + 4)
	if helloPayload then
		local helloPayloadInt = helloPayload:uint8()
		--nw.logInfo("***helloPayloadInt:" .. tonumber(helloPayloadInt))
		if helloPayloadInt == 1 then
			--We are in the Handshake and Client Hello
			--nw.logInfo("Client Hello!")
			nw.createMeta(self.keys["analysis.service"], "ssl client hello")
			
			-- get a tiny payload object of just the next two bytes
			local payload = nw.getPayload(last + 1, last + 2)
			if payload then
				-- those two bytes are the length of the TLS section
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
								--[[
								for index, cipherSuite in ipairs(cipherSuitesTable) do
									--nw.logInfo("cipherSuite[" .. index .. "]: " .. tostring(bit.tohex(cipherSuite,4)))
									cipherSuites = cipherSuites .. tostring(tonumber(cipherSuite)) .. "-"
								end
								--]]
								--nw.logInfo("cipherSuites: ".. cipherSuites)
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
							
							--SSLExtensionLength
							local SSLExtensionTableLength = payload:uint16(position)
							position = position + 2
							--nw.logInfo("SSLExtensionTableLength: " .. tonumber(SSLExtensionTableLength))
							local SSLExtensionTypes = ''
							local ECC = ''
							local EllipticCurvePointFormat = ''
							if SSLExtensionTableLength and SSLExtensionTableLength > 0 then
								--SSLExtension
								--local SSLExtensionTypeTable = {}
								--local SSLExtensionLengthTable = {}
								
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
										--SSLExtensionTypeTable[ExtensionCount] = ExtType
										SSLExtensionTypes = SSLExtensionTypes .. ExtType .. '-'

										--nw.logInfo("ExtensionCount: " .. tonumber(ExtensionCount))
										--nw.logInfo("ExtensionType: " .. tonumber(SSLExtensionTypeTable[ExtensionCount]))

										--position = position + SSLExtensionLength
										--ExtensionPosition = ExtensionPosition + SSLExtensionLength
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
											ECC = ECC:sub(1,-2)
											--local ECCPayload = nw.getPayload(position + 5, position + 5 + 1 + EllipticCurveLength)
											--nw.logInfo("NextWord: " .. bit.tohex(payload:uint16(position),4))
											--nw.logInfo("hexoutfunction: " .. toHexString(ECCPayload))
											
										--Handle EllipticCurvePointFormat	
										--elseif SSLExtensionTypeTable[ExtensionCount] == 11 then
										elseif ExtType == 11 then
										
											local EllipticCurvePointFormatLength = payload:uint8(position)
											--local 
											--position = position + 1
											--nw.logInfo("EllipticCurvePointFormatLength: " .. tonumber(EllipticCurvePointFormatLength))
											
											position = position + 1
											ExtensionPosition = ExtensionPosition + 1
											
											for i=1, EllipticCurvePointFormatLength do
												EllipticCurvePointFormat = EllipticCurvePointFormat .. payload:uint8(position) .. '-'
												position = position + 1
												ExtensionPosition = ExtensionPosition + 1
											end
											EllipticCurvePointFormat = EllipticCurvePointFormat:sub(1,-2)
											--local ECCPayload = nw.getPayload(position + 5, position + 5 + 1 + EllipticCurveLength)
										else
											--Skip over it
											position = position + SSLExtensionLength
											ExtensionPosition = ExtensionPosition + SSLExtensionLength
										end
									end
									ExtensionCount = ExtensionCount + 1
								end
								
								
								--for i=1,SSLExtensionLength/2 do
								--	SSLExtensionTable[i] = payload:uint16(position)
								--	position = position + 2
								--end
								--[[
								for index, SSLExtensionType in ipairs(SSLExtensionTypeTable) do
									--nw.logInfo("SSLExtensionType[" .. index .. "]: " .. tostring(bit.tohex(SSLExtensionType,4)))
									--nw.logInfo("SSLExtensionType[" .. index .. "]: " .. tostring(tonumber(SSLExtensionType)))
									SSLExtensionTypes = SSLExtensionTypes .. tostring(tonumber(SSLExtensionType)) .. "-"
								end
								--]]
								--nw.logInfo("SSLExtensionTypes: ".. SSLExtensionTypes)
								SSLExtensionTypes = SSLExtensionTypes:sub(1,-2)
								--nw.logInfo("SSLExtensionTypes: ".. SSLExtensionTypes)
							end
							
							
							--Create FingerPrint
							local sslFingerprint = tostring(tonumber(version)) .. ',' .. cipherSuites .. ',' .. SSLExtensionTypes .. ',' .. ECC .. ',' .. EllipticCurvePointFormat
							--nw.logInfo("LOG: " .. nwsession.getSource() .. " -> " .. nwsession.getDestination()) 
							--nw.logInfo("sslFingerprint: " .. sslFingerprint)
							
							--[[
							--Calc ja3 hash and create meta
							local ja3md5 = md5.Calc(sslFingerprint)
							--nw.logInfo("md5: " .. ja3md5)
							nw.createMeta(self.keys["ssl.ja3"], ja3md5)
							--Lookup in ja3 table
							if self.ja3[sslFingerprint] then
							
								--nw.logInfo("client: " .. self.ja3[sslFingerprint])
							    nw.createMeta(self.keys["client"], self.ja3[sslFingerprint])
							else 
								--nw.logInfo("client: " .. "unknown")
							    nw.createMeta(self.keys["client"], "unknown")
							end
							--]]
							
							--Calc ja3 hash and create meta
							local ja3md5 = md5.Calc(sslFingerprint)
							--nw.logInfo("md5: " .. ja3md5)
							nw.createMeta(self.keys["ssl.ja3"], ja3md5)
							
							--Lookup in JA3 Hash Table
							if self.ja3hash[ja3md5] then
								--nw.logInfo("client: " .. self.ja3hash[ja3md5])
							    nw.createMeta(self.keys["client"], self.ja3hash[ja3md5])
							else 
								--nw.logInfo("client: " .. "unknown")
							    nw.createMeta(self.keys["client"], "unknown")
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
