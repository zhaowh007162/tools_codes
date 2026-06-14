local JCXX = gg.getTargetInfo();
local DJSFLB={};
local ZDYJLB={};

function NCZH(S)
  if(S==2)then
    return "Jh";
  elseif(S==1)then
    return "Ch";
  elseif(S==4)then
    return "Ca";
  elseif(S==8)then
    return "Cd";
  elseif(S==16)then
    return "Cb";
  elseif(S==262144)then
    return "PS";
  elseif(S==32)then
    return "A";
  elseif(S==65536)then
    return "J";
  elseif(S==64)then
    return "S";
  elseif(S==524288)then
    return "As";
  elseif(S==1048576)then
    return "V";
  elseif(S==-2080896)then
    return "O";
  elseif(S==131072)then
    return "B";
  elseif(S==16384)then
    return "Xa";
  elseif(S==32768)then
    return "Xs";
  end
end

function QNCL(N)
  local x={};
  local z=0;
  local n=gg.getRangesList();
  for v,w in ipairs(n)do
    if w.state == N then
    x[#x+1]=w;
    x[#x].size=w["end"]-w["start"];
    end
  end
  return x,#x;
end

function NCPX(nclb,sj)
  local nclc=#nclb;
  if(sj==1)then
    for i=1,nclc-1 do
      for j=1 ,nclc-1 do
        if(nclb[j].size>nclb[j+1].size)then
          local temp = nclb[j+1];
          nclb[j + 1] = nclb[j];
          nclb[j] = temp;
        end
      end
    end
  elseif(sj==2)then
    for i=1,nclc-1 do
      for j=1 ,nclc-1 do
        if(nclb[j].size<nclb[j+1].size)then
          local temp = nclb[j+1];
          nclb[j + 1] = nclb[j];
          nclb[j] = temp;
        end
      end
    end
  end
  return nclb;
end

function LHSS(data)
  local sssl=0;
  local sssj={};
  if(data.ncpx>0 or data.ncks>0 or data.ncjw<100)then
    local nclb,ncsl=QNCL(NCZH(data.ncfw));
    if(ncsl==0)then
      gg.toast(data.gnm.."开启失败");
      return false;
    end
    local nclb=NCPX(nclb,data.ncpx);
    local ks,GGBox=math.modf(#nclb*(data.ncks*0.01));
    if(ks==0)then
      ks=1;
    end
    local jw,GGBox=math.modf(#nclb*(data.ncjw*0.01));
    if(jw==0)then
      jw=#nclb;
    end
    for i=ks,jw do
      gg.clearResults();
      gg.searchNumber(data.xss.sz, data.xss.lx, false, gg.SIGN_EQUAL, nclb[i]["start"], nclb[i]["end"], 0);
      gg.refineNumber(data.gs.sz, data.gs.lx);
      local sl=gg.getResultsCount();
      if(sl>0)then
        local sj=gg.getResults(sl)
        for j=1,sl do
          sssl=sssl+1;
          sssj[sssl]=sj[j];
        end
      end
      gg.clearResults();
    end
    if(#sssj==0)then
        gg.toast(data.gnm.."开启失败");
        return false;
    end;
    gg.loadResults(sssj);
    gg.getResults(sssl)
  else
    gg.clearResults();
    gg.setRanges(data.ncfw);
    gg.searchNumber(data.xss.sz, data.xss.lx);
    gg.refineNumber(data.gs.sz, data.gs.lx);
    sssl=gg.getResultsCount();
      if(sssl==0)then
        gg.toast(data.gnm.."开启失败");
        return false;
      end;
      sssj=gg.getResults(sssl);
  end
  local xgz=data.xg.sz;
  if(data.zdyjl and ZDYJLB[data.md5])then
    xgz=ZDYJLB[data.md5];
  end
  if(data.zdyxg)then
    local zdy=gg.prompt({data.zdybz},{xgz},{"number"});
    if(zdy)then
      xgz=zdy[1];
      if(data.zdyjl)then
      ZDYJLB[data.md5]=zdy[1];
      end
     else
      gg.clearResults();
      gg.toast(data.gnm.."取消开启");
      return false;
    end;
  end;
  if(data.xgdj==false)then
    gg.editAll(xgz, data.xg.lx);
    gg.clearResults();
    gg.toast(data.gnm.."开启成功");
    return true;
  end;
  if(data.djsf)then
    if(DJSFLB[data.md5])then
      gg.removeListItems(DJSFLB[data.md5]);
    end;
    DJSFLB[data.md5]={};
    for i, v in ipairs(sssj) do
      if v.flags == data.xg.lx then
        v.value = xgz;
        v.freeze = true;
        DJSFLB[data.md5][#DJSFLB[data.md5]+1]=v.address;
      end;
    end;
   else
    for i, v in ipairs(sssj) do
      if v.flags == data.xg.lx then
        v.value = xgz;
        v.freeze = true;
      end;
    end;
  end;
  gg.addListItems(sssj);
  gg.clearResults();
  gg.toast(data.gnm.."开启成功");
  return true;
end;

function PYXG(M,md5,S,G)
  local sfs=0;
  local sfl=0;
  if(DJSFLB[md5])then
    sfl=#DJSFLB[md5];
    gg.removeListItems(DJSFLB[md5]);
  end;
  DJSFLB[md5]={};
  local zdyjmsj={};
  zdyjmsj.t={};
  zdyjmsj.s={};
  zdyjmsj.r={};
  zdyjmsj.j={};
  local zdyjl=0;
  for i,v in pairs(G) do
    if(v.zd)then
      zdyjl=zdyjl+1;
      zdyjmsj.t[zdyjl]=v.bz;
      if(v.jl and ZDYJLB[md5])then
        zdyjmsj.s[zdyjl]=ZDYJLB[md5][zdyjl];
       else
        zdyjmsj.s[zdyjl]=v.sz;
      end
      zdyjmsj.r[zdyjl]="number";
      zdyjmsj.j[zdyjl]=i
    end;
  end;
  if(zdyjl>0)then
    local zdy=gg.prompt(zdyjmsj.t,zdyjmsj.s,zdyjmsj.r);
    if(zdy)then
      ZDYJLB[md5]={};
      for i=1,#zdyjmsj.j do
        ZDYJLB[md5][i]=zdy[i];
        G[zdyjmsj.j[i]].sz=zdy[i];
      end;
     else
      gg.toast(M.."取消开启");
      return false;
    end;
  end;
  local xg,xgs,dj,djs={},0,{},0;
  for i,v in ipairs(S)do
    for I,V in ipairs(G)do
      local shuju={};
      shuju["address"]=v.address+V.py;
      shuju["flags"]=V.lx;
      shuju["value"]=V.sz;
      if(V.dj)then
        shuju["freeze"]=true;
        djs=djs+1;
        dj[djs]=shuju;
        if(V.sf)then
          sfs=sfs+1;
          DJSFLB[md5][sfs]=v.address+V.py;
        end;
       else
        xgs=xgs+1;
        xg[xgs]=shuju;
      end;
    end;
  end;
  gg.setValues(xg);
  gg.addListItems(dj);
  gg.toast(M.."开启成功\n修改"..xgs.."|冻结"..djs.."|释放"..sfl);
end;

function TZMPT(ztz,ftz)
  local linshishuju;
  local xinshuju;
  local ftzs=#ftz
  for i=1,ftzs do
    linshishuju={};
    xinshuju={};
    for ii,v in ipairs(ztz)do
      linshishuju[ii]={};
      linshishuju[ii].address=v.address+ftz[i].py;
      linshishuju[ii].flags=ftz[i].lx;
    end;
    for ii,v in ipairs(gg.getValues(linshishuju))do
      if(v.value==ftz[i].sz)then
        xinshuju[#xinshuju+1]=ztz[ii]
      end;
    end;
    if(#xinshuju==0)then
      return false;
    end;
    ztz=xinshuju;
  end;
  return ztz
end;

function PYSS(data)
  local sssl=0;
  local sssj={};
  if(data.ncpx>0 or data.ncks>0 or data.ncjw<100)then
    local nclb,ncsl=QNCL(NCZH(data.ncfw));
    if(ncsl==0)then
      gg.toast(data.gnm.."开启失败");
      return false;
    end
    local nclb=NCPX(nclb,data.ncpx);
    local ks,GGBox=math.modf(#nclb*(data.ncks*0.01));
    if(ks==0)then
      ks=1;
    end
    local jw,GGBox=math.modf(#nclb*(data.ncjw*0.01));
    if(jw==0)then
      jw=#nclb;
    end
    for i=ks,jw do
      gg.clearResults();
      gg.searchNumber(data.ztz.sz, data.ztz.lx, false, gg.SIGN_EQUAL, nclb[i]["start"], nclb[i]["end"], 0);
      local sl=gg.getResultsCount();
      if(sl>0)then
        local sj=gg.getResults(sl)
        for j=1,sl do
          sssl=sssl+1;
          sssj[sssl]=sj[j];
        end
      end
      gg.clearResults();
    end
    if(#sssj==0)then
        gg.toast(data.gnm.."开启失败\n未找到主特征");
        return false;
    end;
    gg.clearResults();
  else
    gg.clearResults();
    gg.setRanges(data.ncfw);
    gg.searchNumber(data.ztz.sz, data.ztz.lx);
    sssl=gg.getResultsCount();
    if(sssl<1)then
      gg.toast(data.gnm.."开启失败\n未找到主特征");
      return false;
    end;
    sssj=gg.getResults(sssl);
    gg.clearResults();
  end
  sssj=TZMPT(sssj,data.ftz);
  if(sssj)then
    PYXG(data.gnm,data.md5,sssj,data.xgz);
   else
    gg.toast(data.gnm.."开启失败\n未找到副特征");
    return false;
  end;
end;

function ZZTZ(mk,zzlt)
  local zzlts=#zzlt;
  if(zzlts==0)then
    return false;
  end
  local sjlx;
  if(JCXX.x64)then
    sjlx=32;
   else
    sjlx=4;
  end;
  local shuzu={};
  shuzu[1] = {};
  shuzu[1].address = mk.start + zzlt[1];
  shuzu[1].flags = sjlx;
  if zzlts ~= 1 then
    for i = 2, zzlts do
      local dushuju = gg.getValues(shuzu);
      shuzu = {}
      for _ in pairs(dushuju) do
        if not JCXX.x64 then
          dushuju[_].value = dushuju[_].value & 0xFFFFFFFF
        end
        shuzu[1] = {}
        shuzu[1].address = dushuju[_].value + zzlt[i]
        shuzu[1].flags = sjlx
      end;
    end;
  end;
  return shuzu;
end;

function ZZSS(data)
  local mklb={};
  local mklbs=0;
  local t = gg.getRangesList('^/data/*'..data.mkm..'*$');
  for i,v in pairs(t) do
    if(v.type:sub(1, 1)=="r" and (v.state==NCZH(data.nclx)))then
      mklbs=mklbs+1;
      mklb[mklbs]=v;
    end;
  end;
  if(mklbs==0)then
    gg.toast(data.gnm.."开启失败\n没找到模块头");
    return false;
  end
  local k,j;
  if(data.xh==0)then
    k=1;
    j=mklbs;
   else
    if(mklbs<data.xh)then
      gg.toast(data.gnm.."开启失败\n无指定模块头");
      return false;
    end
    k=data.xh;
    j=data.xh;
  end
  for i=k,j do
    local shuzu= ZZTZ(mklb[i],data.zzlb);
    if(shuzu==false)then
      gg.toast(data.gnm.."开启失败\n指针跳转失败");
      return false;
    end
    local tzpd=TZMPT(shuzu,data.ftz);
    if(tzpd)then
      PYXG(data.gnm,data.md5,shuzu,data.xgz);
      return true;
    end
    if(i==j)then
      gg.toast(data.gnm.."开启失败\n未找到副特征");
      return false;
    end;
  end
end;if(true)then
	gg.alert("公告：解锁英雄\n登陆页面开\n再进入单机","收到");
end
local xsui = true;
while(true)do
	if(gg.isVisible(true))or xsui then
		xsui=false;
		gg.setVisible(false);
		local gnxz=gg.multiChoice({'12+改单机','解锁韩信★武则天','退出脚本',},{false,false,false,false,},'');
		if(gnxz)then
			if(gnxz[1])then
				LHSS({['ncfw']=32,['ncpx']=0,['ncks']=0,['ncjw']=100,['xss']={['sz']='3449',['lx']=4,},['gs']={['sz']='',['lx']=4,},['xg']={['sz']='3448',['lx']=4,},['xgdj']=false,['djsf']=false,['zdyxg']=false,['zdybz']='',['gnm']='12+改单机',['md5']='318d60e8acfadd1aa3be16351e8b6220',})
			end
			if(gnxz[2])then
				PYSS({['gnm']='解锁韩信',['md5']='c7c0a426c23a59f6f3b4ee9924a4f23e',['ncfw']=-2080896,['ncpx']=0,['ncks']=0,['ncjw']=100,['ztz']={['lx']=4,['sz']='1987865618',},['ftz']={{['py']=8,['lx']=4,['sz']='0',},},['xgz']={{['py']=-4,['lx']=4,['sz']='1',['zd']=false,['bz']='',['dj']=false,['sf']=false,},},})
				PYSS({['gnm']='解锁武则天',['md5']='a42ab00a4180b444ba88f363e96230b9',['ncfw']=-2080896,['ncpx']=0,['ncks']=0,['ncjw']=100,['ztz']={['lx']=4,['sz']='-804654372',},['ftz']={{['py']=8,['lx']=4,['sz']='0',},},['xgz']={{['py']=-4,['lx']=4,['sz']='1',['zd']=false,['bz']='',['dj']=false,['sf']=false,},},})
			end
			if(gnxz[3])then
				os.exit();
			end
		end;
		gg.setVisible(false);
	end;
end;
