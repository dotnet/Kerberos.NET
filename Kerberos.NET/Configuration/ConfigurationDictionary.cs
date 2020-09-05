using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Kerberos.NET.Configuration
{
    [DebuggerDisplay("{backing}")]
    internal class ConfigurationDictionary<TKey, TValue> : IDictionary<TKey, TValue>, IDictionary
    {
        private static readonly ConfigurationSectionList DefaultValues = new ConfigurationSectionList();
        private readonly Dictionary<TKey, TValue> backing = new Dictionary<TKey, TValue>();

        public TValue this[TKey key]
        {
            get
            {
                if (!this.TryGetValue(key, out TValue value))
                {
                    value = (TValue)DefaultValues.CreateProperty(typeof(TValue), string.Empty);

                    this.backing[key] = value;
                }

                return value;
            }
            set
            {
                this.backing[key] = value;
            }
        }

        object IDictionary.this[object key]
        {
            get => this[(TKey)key];
            set => this[(TKey)key] = (TValue)value;
        }

        public ICollection<TKey> Keys => this.backing.Keys;

        public ICollection<TValue> Values => this.backing.Values;

        public int Count => this.backing.Count;

        public bool IsReadOnly => ((IDictionary<TKey, TValue>)this.backing).IsReadOnly;

        bool IDictionary.IsFixedSize => ((IDictionary)this.backing).IsFixedSize;

        ICollection IDictionary.Keys => ((IDictionary)this.backing).Keys;

        ICollection IDictionary.Values => ((IDictionary)this.backing).Values;

        bool ICollection.IsSynchronized => ((IDictionary)this.backing).IsSynchronized;

        object ICollection.SyncRoot => ((IDictionary)this.backing).SyncRoot;

        public void Add(TKey key, TValue value)
        {
            this.backing.Add(key, value);
        }

        public void Clear()
        {
            this.backing.Clear();
        }

        public bool Contains(KeyValuePair<TKey, TValue> item)
        {
            return this.backing.Contains(item);
        }

        public bool ContainsKey(TKey key)
        {
            return this.backing.ContainsKey(key);
        }

        public void CopyTo(KeyValuePair<TKey, TValue>[] array, int arrayIndex)
        {
            ((IDictionary<TKey, TValue>)this.backing).CopyTo(array, arrayIndex);
        }

        public IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
        {
            return this.backing.GetEnumerator();
        }

        public bool Remove(TKey key)
        {
            return this.backing.Remove(key);
        }

        public bool Remove(KeyValuePair<TKey, TValue> item)
        {
            return ((IDictionary<TKey, TValue>)this.backing).Remove(item);
        }

        public bool TryGetValue(TKey key, out TValue value)
        {
            return this.backing.TryGetValue(key, out value);
        }

        void ICollection<KeyValuePair<TKey, TValue>>.Add(KeyValuePair<TKey, TValue> item)
        {
            ((IDictionary<TKey, TValue>)this.backing).Add(item);
        }

        void IDictionary.Add(object key, object value)
        {
            ((IDictionary)this.backing).Add(key, value);
        }

        bool IDictionary.Contains(object key)
        {
            return ((IDictionary)this.backing).Contains(key);
        }

        void ICollection.CopyTo(Array array, int index)
        {
            ((IDictionary)this.backing).CopyTo(array, index);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.backing.GetEnumerator();
        }

        IDictionaryEnumerator IDictionary.GetEnumerator()
        {
            return ((IDictionary)this.backing).GetEnumerator();
        }

        void IDictionary.Remove(object key)
        {
            ((IDictionary)this.backing).Remove(key);
        }
    }
}
