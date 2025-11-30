# [VateX – eXtend the Edge](https://github.com/lastime1650/VateX)

<div align="center">
  <img
    src="https://github.com/lastime1650/VateX/blob/main/images/VATEX.png"
    alt="VATEX LOGO"
    width="500"
  />
</div>

---

# VateX Series - VateX XIPHOS XDR

<div align="center">
  <img
    src="https://github.com/lastime1650/VateX/blob/mainv2/images/VATEX_XDR_RENDERED.png"
    alt="VATEX NOVA"
    width="400"
  />
</div>

---

## Structure

![initial](https://github.com/lastime1650/VATEX_NOVA_AI/blob/main/VATEX_NOVA_AI_V3.png)

---

**XIPHOS** means *sword* in Latin — symbolizing precision and defense.  
Our Extended Detection and Response platform integrates endpoint, network, and application data into a unified, proactive defense system — cutting through threats with unparalleled accuracy and automation. 🤖🛡️

---

## Key Components

1. **Only RestAPI**
2. **Log Combine**

---

## Examples

> [!NOTE]
> 
> it depends with **[VateX SAPIENTIA (SIEM)](https://github.com/lastime1650/VATEX_SAPIENTIA_SIEM)**
>

---

# Structure

![initial](https://github.com/lastime1650/VateX_XIPHOS_XDR/blob/main/XDR_STRUCTURE.png)

For XIPHOS XDR, we receive various types of solution log 2 from SIEM and provide two different methods of analysis.

## 1. Timestamp based 

![initial](https://github.com/lastime1650/VateX_XIPHOS_XDR/blob/main/XDR_Analysis_Timestamp.png)

The "Timestamp" method collects and analyzes "all logs" that fall within any set time range.


## 2. Anchor based

![initial](https://github.com/lastime1650/VateX_XIPHOS_XDR/blob/main/XDR_Analysis_Anchor.png)

The "Anchor" method identifies the "Root Log Session" of a particular solution, combines the logarithms of other solutions associated with it to reduce noise, and provides a complete timeline and analysis direction.

> [!TIP]
> 
> Anchor based Analyzed Output Preview
>
> ![initial](https://github.com/lastime1650/VateX_XIPHOS_XDR/blob/main/AnchorSamplePreview.png)
>
> View the Anchor-based analysis above.
> 
> Run "PING.EXE" in EDR,
> After that, you can check the sequence detected by the sensor in the NDR.
>
