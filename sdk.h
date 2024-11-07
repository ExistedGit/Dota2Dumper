#pragma once
#include <Windows.h>
#include <iostream>
#include <cstdint>
#include <string_view>
#include <vector>
#include <emmintrin.h>

#define DOTA2

template <class T>
class CUtlVector
{
public:
	uint32_t m_Size;
	T* m_pElements;
	uint32_t m_Capacity;

	T& operator[](int i) const 
	{
		return m_pElements[i];
	}

	T& at(int i) const  {
		return m_pElements[i];
	}

	T* begin() const {
		return m_pElements;
	}

	T* end() const {
		return m_pElements + m_Size;
	}

	int size() const
	{
		return m_Size;
	}
};
struct __declspec(align(16)) TSLNodeBase_t {
    TSLNodeBase_t* Next; // name to match Windows
};

typedef __m128i int128;

union __declspec(align(16)) TSLHead_t {
    struct Value_t {
        TSLNodeBase_t* Next;
        std::int16_t Depth;
        std::int16_t Sequence;
        std::int32_t Padding;
    } value;

    struct Value32_t {
        TSLNodeBase_t* Next_do_not_use_me;
        std::int32_t DepthAndSequence;
    } value32;

    int128 value64x128;
};
class __declspec(align(16)) CTSListBase {
public:
    [[nodiscard]] int Count() const {
        return m_Head.value.Depth;
    }

public:
    TSLHead_t m_Head;
};

using UtlTsHashHandleT = std::uint64_t;
using CThreadMutex = std::array<char, 56>;
using CThreadSpinRWLock = std::array<char, 24>;
using CInterlockedInt = volatile int;

class CUtlMemoryPoolBaseV2 {
public:
    struct FreeList_t {
        FreeList_t* m_pNext;
    };

    class CBlob {
    public:
        CBlob* m_pNext;
        int m_NumBytes; // Number of bytes in this blob.
        char m_Data[1];
        char m_Padding[3]; // to int align the struct
    };

    int m_BlockSize{};
    int m_BlocksPerBlob{};

    int m_GrowMode{};

    CInterlockedInt m_BlocksAllocated{};
    CInterlockedInt m_PeakAlloc{};
    std::uint16_t m_nAlignment{};
    std::uint16_t m_NumBlobs{};
    
    CTSListBase m_FreeBlocks{};

    int m_AllocAttribute{};

    CThreadMutex m_Mutex{};

    CBlob* m_pBlobHead{};

    int m_TotalSize{}; // m_BlocksPerBlob * (m_NumBlobs + 1) + (m_nAligment + 14)
};
template <class KEYTYPE = std::uint64_t>
class CUtlTSHashGenericHash {
public:
    static int Hash(const KEYTYPE& key, int nBucketMask) {
        int nHash = HashIntConventional((std::uint64_t)key);
        if (nBucketMask <= USHRT_MAX) {
            nHash ^= (nHash >> 16);
        }
        if (nBucketMask <= UCHAR_MAX) {
            nHash ^= (nHash >> 8);
        }
        return (nHash & nBucketMask);
    }

    static bool Compare(const KEYTYPE& lhs, const KEYTYPE& rhs) {
        return lhs == rhs;
    }
};


template <class T, class Keytype = std::uint64_t, int BucketCount = 256, class HashFuncs = CUtlTSHashGenericHash<Keytype>>
class CUtlTSHashV2 {
public:
    // Invalid handle.
    static UtlTsHashHandleT InvalidHandle() {
        return static_cast<UtlTsHashHandleT>(0);
    }

    // Returns the number of elements in the hash table
    [[nodiscard]] int BlockSize() const {
        return m_EntryMemory.m_BlockSize;
    }
    [[nodiscard]] int PeakAlloc() const {
        return m_EntryMemory.m_PeakAlloc;
    }
    [[nodiscard]] int BlocksAllocated() const {
        return m_EntryMemory.m_BlocksAllocated;
    }
    [[nodiscard]] int Count() const {
        return BlocksAllocated() == 0 ? PeakAlloc() : BlocksAllocated();
    }

    // Returns elements in the table
    std::vector<T> GetElements(int nFirstElement = 0);

private:
    template <typename Predicate>
    std::vector<T> merge_without_duplicates(const std::vector<T>& allocated_list, const std::vector<T>& un_allocated_list, Predicate pred);

public:
    class HashAllocatedBlob_t {
    public:
        HashAllocatedBlob_t* m_unAllocatedNext; // 0x0000
        char pad_0008[8]; // 0x0008
        T m_unAllocatedData; // 0x0010
        char pad_0018[8]; // 0x0018
    }; // Size: 0x0020

    // Templatized for memory tracking purposes
    template <typename Data_t>
    struct HashFixedDataInternal_t {
        Keytype m_uiKey;
        HashFixedDataInternal_t<Data_t>* m_pNext;
        Data_t m_Data;
    };

    typedef HashFixedDataInternal_t<T> HashFixedData_t;

    class HashBucket_t {
    public:
        CThreadSpinRWLock m_AddLock; // 0x0000
        HashFixedData_t* m_pFirst; // 0x0020
        HashFixedData_t* m_pFirstUncommitted; // 0x0020
    }; // Size: 0x0028
    
    static_assert(sizeof(HashBucket_t) == 0x28);

    CUtlMemoryPoolBaseV2 m_EntryMemory;

    std::array<HashBucket_t, BucketCount> m_aBuckets;
    bool m_bNeedsCommit{};
    CInterlockedInt m_ContentionCheck;
};
static_assert(sizeof(CUtlMemoryPoolBaseV2) == 0x80);
template <typename T>
bool ptr_compare(const T& item1, const T& item2) {
    return item1 == item2;
}

template <class T, class Keytype, int BucketCount, class HashFuncs>
template <typename Predicate>
inline std::vector<T> CUtlTSHashV2<T, Keytype, BucketCount, HashFuncs>::merge_without_duplicates(const std::vector<T>& allocated_list,
    const std::vector<T>& un_allocated_list, Predicate pred) {
    std::vector<T> merged_list = allocated_list;

    for (const auto& item : un_allocated_list) {
        if (std::ranges::find_if(allocated_list, [&](const T& elem) { return pred(elem, item); }) == allocated_list.end()) {
            merged_list.push_back(item);
        }
    }

    return merged_list;
}
template<typename T = uintptr_t>
inline bool IsValidReadPtr(T p) {
    if (!p)
        return false;
    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi)))
        return false;
    if (!(mbi.State & MEM_COMMIT))
        return false;
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return false;
    return true;
}

template <class T, class Keytype, int BucketCount, class HashFuncs>
std::vector<T> CUtlTSHashV2<T, Keytype, BucketCount, HashFuncs>::GetElements(int nFirstElement) {
    int n_count = BlocksAllocated();
    std::vector<T> AllocatedList;
    if (n_count > 0) {
        int nIndex = 0;
        for (int i = 0; i < BucketCount; i++) {
            const HashBucket_t& bucket = m_aBuckets[i];
            for (HashFixedData_t* pElement = bucket.m_pFirstUncommitted; pElement; pElement = pElement->m_pNext) {
                if (--nFirstElement >= 0)
                    continue;

                if (!IsValidReadPtr(pElement) || pElement->m_Data == nullptr)
                    continue;

                AllocatedList.emplace_back(pElement->m_Data);
                ++nIndex;

                if (nIndex >= n_count)
                    break;
            }
        }
    }

    /// @note: @og: basically, its hacky-way to obtain first-time commited information to memory
#if defined(CS2_OLD)
    n_count = PeakAlloc();
#elif defined(DOTA2) || defined(CS2) || defined(DEADLOCK)
    n_count = PeakAlloc() - BlocksAllocated();
#endif
    std::vector<T> unAllocatedList;
    if (n_count > 0) {
        int nIndex = 0;
        auto m_unBuckets = *reinterpret_cast<HashAllocatedBlob_t**>(&m_EntryMemory.m_FreeBlocks.m_Head.value32);
        for (auto unallocated_element = m_unBuckets; unallocated_element; unallocated_element = unallocated_element->m_unAllocatedNext) {
            if (unallocated_element->m_unAllocatedData == nullptr)
                continue;

            unAllocatedList.emplace_back(unallocated_element->m_unAllocatedData);
            ++nIndex;

            if (nIndex >= n_count)
                break;
        }
    }

#if defined(CS2_OLD)
    return unAllocatedList.size() > AllocatedList.size() ? unAllocatedList : AllocatedList;
#elif defined(DOTA2) || defined(CS2) || defined(DEADLOCK)
    return merge_without_duplicates(AllocatedList, unAllocatedList, ptr_compare<T>);
#endif
}
