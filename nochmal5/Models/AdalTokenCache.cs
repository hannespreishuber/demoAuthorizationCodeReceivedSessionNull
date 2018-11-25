using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data.Entity;
using System.Linq;
using System.Web;
using System.Web.Security;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace nochmal5.Models
{
    public class ADALTokenCache : TokenCache
    {
        private ApplicationDbContext db = new ApplicationDbContext();
        private string userId;
        private UserTokenCache Cache;

        public ADALTokenCache(string signedInUserId)
        {
            // den Cache dem aktuellen Benutzer der Web-App zuordnen
            userId = signedInUserId;
            this.AfterAccess = AfterAccessNotification;
            this.BeforeAccess = BeforeAccessNotification;
            this.BeforeWrite = BeforeWriteNotification;
            // den Eintrag in der Datenbank nachschlagen
            Cache = db.UserTokenCacheList.FirstOrDefault(c => c.webUserUniqueId == userId);
            // den Eintrag im Arbeitsspeicher speichern
            this.Deserialize((Cache == null) ? null : MachineKey.Unprotect(Cache.cacheBits,"ADALCache"));
        }

        // die Datenbank bereinigen
        public override void Clear()
        {
            base.Clear();
            var cacheEntry = db.UserTokenCacheList.FirstOrDefault(c => c.webUserUniqueId == userId);
            db.UserTokenCacheList.Remove(cacheEntry);
            db.SaveChanges();
        }

        // Eine Benachrichtigung, die ausgelöst wird, bevor ADAL auf den Cache zugreift.
        // Hier besteht die Möglichkeit, die In-Memory-Kopie aus der Datenbank zu aktualisieren, wenn die In-Memory-Version veraltet ist.
        void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            if (Cache == null)
            {
                // erstmaliger Zugriff
                Cache = db.UserTokenCacheList.FirstOrDefault(c => c.webUserUniqueId == userId);
            }
            else
            { 
                // letzten Schreibvorgang aus der Datenbank abrufen
                var status = from e in db.UserTokenCacheList
                             where (e.webUserUniqueId == userId)
                select new
                {
                    LastWrite = e.LastWrite
                };

                // wenn die In-Memory-Kopie älter als die persistente Kopie ist
                if (status.First().LastWrite > Cache.LastWrite)
                {
                    // aus dem Speicher lesen, In-Memory-Kopie aktualisieren
                    Cache = db.UserTokenCacheList.FirstOrDefault(c => c.webUserUniqueId == userId);
                }
            }
            this.Deserialize((Cache == null) ? null : MachineKey.Unprotect(Cache.cacheBits, "ADALCache"));
        }

        // Eine Benachrichtigung, die ausgelöst wird, nachdem ADAL auf den Cache zugegriffen hat.
        // Wenn die Kennzeichnung "HasStateChanged" festgelegt ist, hat ADAL den Inhalt des Caches geändert.
        void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // wenn sich der Zustand geändert hat
            if (this.HasStateChanged)
            {
                if (Cache == null)
                {
                    Cache = new UserTokenCache
                    {
                        webUserUniqueId = userId
                    };
                }

                Cache.cacheBits = MachineKey.Protect(this.Serialize(), "ADALCache");
                Cache.LastWrite = DateTime.Now;

                // die Datenbank und den letzten Schreibvorgang aktualisieren 
                db.Entry(Cache).State = Cache.UserTokenCacheId == 0 ? EntityState.Added : EntityState.Modified;
                db.SaveChanges();
                this.HasStateChanged = false;
            }
        }

        void BeforeWriteNotification(TokenCacheNotificationArgs args)
        {
            // wenn Sie sicherstellen möchten, dass kein gleichzeitiger Schreibvorgang stattfindet, verwenden Sie diese Benachrichtigung, um den Eintrag zu sperren.
        }

        public override void DeleteItem(TokenCacheItem item)
        {
            base.DeleteItem(item);
        }
    }
}
