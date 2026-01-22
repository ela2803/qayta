```mermaid
sequenceDiagram
    actor Imzolovchi
    participant Tizim
    participant QabulQiluvchi

    Imzolovchi->>Tizim: Hujjatni yuboradi
    Tizim->>Tizim: Hash yaratadi
    Tizim->>Tizim: Private Key bilan imzolaydi
    Tizim-->>Imzolovchi: Elektron imzo

    Imzolovchi->>QabulQiluvchi: Hujjat + Imzo
    QabulQiluvchi->>QabulQiluvchi: Public Key bilan tekshiradi
```
