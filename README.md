# monitor

Rendszerek elérhetőségi monitorja. GitHub Actions 10 percenként lefuttatja a `check.mjs`-t, amely:

- HTTP-ellenőrzést végez a `services.json`-ban felsorolt nyilvános végpontokon (hibánál 2 újrapróba, 10 mp szünettel),
- olvassa a healthchecks.io-ról az otthoni szívverések (Air, Shelly) állapotát,
- az eredményt Cloudflare R2-be írja (aktuális állapot + nyers 48 óra + napi összesítés),
- a futás végén pingeli a healthchecks.io-t — ha a monitor leáll, onnan jön az egyetlen e-mail-riasztás.

Hiányzó mérés nem jelent "zöldet". A titkok kizárólag GitHub Secrets-ben vannak; a repóban csak kód és a nyilvános végpontlista található.

Helyi próba (nincs írás/ping): `DRY=1 node check.mjs` a megfelelő környezeti változókkal.
